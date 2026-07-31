/*
 * labsentry - sovereign AI-lab auditor + image pipeline (pure C, zero-dep)
 *
 * Subcommands:
 *   scan   walk roots, classify + hash assets, store SQLite catalog, emit JSON
 *   ports  probe known service ports, flag conflicts (e.g. Snap Prometheus :9090)
 *   gpu    report visible GPUs
 *   doctor run scan+ports+gpu and print a health verdict
 *   img    image hygiene: rename to UUID + strip privacy metadata (PNG/JPEG/WebP)
 *
 * Build: see Makefile. Statically links sqlite3.c + sha256.c. No external runtime.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>

#include "sha256.h"
#include "sqlite3.h"

/* ---------- config ---------- */
#define PATH_MAXLEN 4096
#define HASH_CHUNK  (1 << 16)
#define DEFAULT_LARGE_GB 10
#define DEFAULT_MAXHASH_MB 0   /* 0 = hash everything */
#define DEFAULT_MAXDEPTH 64

/* ---------- globals / options ---------- */
static sqlite3 *g_db = NULL;
static FILE *g_json = NULL;
static long g_count = 0, g_dupes = 0, g_viol = 0, g_bytes = 0;
static int g_maxhash_mb = DEFAULT_MAXHASH_MB;
static int g_maxdepth = DEFAULT_MAXDEPTH;
static long g_large_gb = DEFAULT_LARGE_GB;

/* seen-hash linked list for dedupe */
typedef struct Seen { char hex[65]; char path[PATH_MAXLEN]; struct Seen *next; } Seen;
static Seen *g_seen = NULL;

/* known service ports: name, port, expected */
typedef struct { const char *name; int port; int expect; } SvcPort;
static SvcPort PORTS[] = {
    {"ollama",11434,1}, {"comfyui",8188,1}, {"open-webui",3000,1},
    {"prometheus-snap",9090,0}, {"http-alt",8080,0}, {"http",8000,0},
    {"grafana",3000,0},
};
#define NPORTS (int)(sizeof(PORTS)/sizeof(PORTS[0]))

/* ---------- helpers ---------- */
static void die(const char *m){ fprintf(stderr,"FATAL: %s: %s\n", m, strerror(errno)); exit(1); }
static const char *now_iso(void){
    static char buf[32]; time_t t=time(NULL); struct tm *tm=gmtime(&t);
    strftime(buf,sizeof buf,"%Y-%m-%dT%H:%M:%SZ",tm); return buf;
}
static void hex256(const uint8_t h[32], char out[65]){
    static const char *d="0123456789abcdef"; int i;
    for(i=0;i<32;i++){ out[i*2]=d[h[i]>>4]; out[i*2+1]=d[h[i]&15]; } out[64]=0;
}
static int endswith(const char *s, const char *suf){
    size_t a=strlen(s), b=strlen(suf); return a>=b && !strcmp(s+a-b,suf);
}
static const char *basename_of(const char *p){
    const char *b=strrchr(p,'/'); return b?b+1:p;
}

/* classify by extension; returns static string type */
static const char *classify(const char *path){
    if(endswith(path,".gguf")) return "gguf";
    if(endswith(path,".safetensors")) return "safetensors";
    if(endswith(path,".ckpt")) return "checkpoint";
    if(endswith(path,".pt")||endswith(path,".bin")||endswith(path,".pth")) return "pytorch";
    if(endswith(path,".lora")||endswith(path,"-lora.safetensors")) return "lora";
    if(endswith(path,".safetensors.lora")) return "lora";
    if(endswith(path,".onnx")) return "onnx";
    if(endswith(path,".png")||endswith(path,".jpg")||endswith(path,".jpeg")||endswith(path,".webp")||endswith(path,".bmp")) return "image";
    if(endswith(path,".mp4")||endswith(path,".mov")||endswith(path,".webm")) return "video";
    if(endswith(path,".json")||endswith(path,".yaml")||endswith(path,".yml")) return "config";
    if(endswith(path,".node")||endswith(path,".o")||endswith(path,".so")||endswith(path,".a")) return "native-build";
    if(endswith(path,".zip")||endswith(path,".tar")||endswith(path,".gz")) return "archive";
    return "other";
}

/* should this path be flagged as native build cache wrongly on storage? */
static int is_native_build_on_storage(const char *path, const char *mount){
    if(strncmp(mount,"/mnt",4)!=0) return 0; /* only storage roots */
    char *low=strdup(path); /* compare lowercased substring markers */
    char *p=low; while(*p){ *p=tolower((unsigned char)*p); p++; }
    int bad = strstr(low,"node-gyp") || strstr(low,"playwright") ||
              strstr(low,".npm") || strstr(low,"ccache") ||
              strstr(low,"electron") || strstr(low,"pip-cache") ||
              strstr(low,".cache/mozilla") || strstr(low,"node_modules");
    free(low);
    if(bad) return 1;
    /* native object artifacts */
    if(endswith(path,".o")||endswith(path,".so")||endswith(path,".a")||endswith(path,".node")) return 1;
    return 0;
}

/* ---------- sqlite ---------- */
static void db_open(const char *path){
    if(sqlite3_open(path,&g_db)!=SQLITE_OK){ fprintf(stderr,"db open: %s\n",sqlite3_errmsg(g_db)); exit(1); }
    sqlite3_exec(g_db,
        "CREATE TABLE IF NOT EXISTS assets("
        "path TEXT PRIMARY KEY, size INTEGER, type TEXT, sha256 TEXT, "
        "mtime INTEGER, mount TEXT, violation TEXT);",NULL,NULL,NULL);
}
static void db_insert(const char *path,long size,const char *type,const char *sha,
                      long mtime,const char *mount,const char *viol){
    char *err=NULL;
    char sql[PATH_MAXLEN+512];
    char *e_path=sqlite3_mprintf("%q",path);
    (void)err;
    char *e_type=sqlite3_mprintf("%q",type);
    char *e_mount=sqlite3_mprintf("%q",mount);
    char *e_viol=sqlite3_mprintf("%q",viol?viol:"");
    snprintf(sql,sizeof sql,
        "INSERT OR REPLACE INTO assets(path,size,type,sha256,mtime,mount,violation)"
        " VALUES('%s',%ld,'%s','%s',%ld,'%s','%s');",
        e_path,size,e_type,sha,mtime,e_mount,e_viol);
    sqlite3_exec(g_db,sql,NULL,NULL,&err);
    if(err){ fprintf(stderr,"db insert err: %s\n",err); sqlite3_free(err); }
    sqlite3_free(e_path); sqlite3_free(e_type); sqlite3_free(e_mount); sqlite3_free(e_viol);
}

/* ---------- walker ---------- */
static int file_sha256(const char *path, char out[65]){
    int fd=open(path,O_RDONLY);
    if(fd<0) return -1;
    struct stat st; if(fstat(fd,&st)!=0){ close(fd); return -1; }
    if(g_maxhash_mb>0 && st.st_size > (off_t)g_maxhash_mb*1024*1024){
        close(fd); out[0]=0; return 1; /* skipped, too big */
    }
    SHA256_CTX ctx; sha256_init(&ctx);
    uint8_t buf[HASH_CHUNK]; ssize_t n;
    while((n=read(fd,buf,sizeof buf))>0) sha256_update(&ctx,buf,(size_t)n);
    close(fd);
    uint8_t h[32]; sha256_final(&ctx,h); hex256(h,out);
    return 0;
}

static int mount_of(const char *path, char out[PATH_MAXLEN]){
    /* pick longest known storage prefix */
    static const char *roots[] = {"/mnt/ai-storage","/",0};
    int best=-1; size_t bl=0;
    for(int i=0;roots[i];i++){
        size_t l=strlen(roots[i]);
        if(strncmp(path,roots[i],l)==0 && l>bl){ bl=l; best=i; }
    }
    if(best<0){ strcpy(out,"/"); return 0; }
    strncpy(out,roots[best],PATH_MAXLEN-1); out[PATH_MAXLEN-1]=0;
    return 0;
}

static Seen *seen_find(const char *hex){
    for(Seen *s=g_seen;s;s=s->next) if(!strcmp(s->hex,hex)) return s;
    return NULL;
}
static void seen_add(const char *hex,const char *path){
    Seen *s=calloc(1,sizeof *s);
    strncpy(s->hex,hex,64); s->hex[64]=0;
    strncpy(s->path,path,PATH_MAXLEN-1); s->path[PATH_MAXLEN-1]=0;
    s->next=g_seen; g_seen=s;
}

static void walk(const char *root,int depth){
    if(depth>g_maxdepth) return;
    DIR *d=opendir(root);
    if(!d){ if(errno!=ENOENT) fprintf(stderr,"opendir %s: %s\n",root,strerror(errno)); return; }
    struct dirent *e;
    while((e=readdir(d))){
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,"..")) continue;
        char full[PATH_MAXLEN];
        snprintf(full,sizeof full,"%s/%s",root,e->d_name);
        struct stat st;
        if(lstat(full,&st)!=0) continue;
        if(S_ISDIR(st.st_mode)){
            if(strcmp(e->d_name,".git")==0) continue; /* skip repo internals */
            walk(full,depth+1);
        } else if(S_ISREG(st.st_mode)){
            g_count++; g_bytes+=st.st_size;
            const char *type=classify(full);
            char sha[65]; int r=file_sha256(full,sha);
            const char *viol=NULL;
            char mount[PATH_MAXLEN]; mount_of(full,mount);
            if(is_native_build_on_storage(full,mount)) viol="native-build-cache-on-storage";
            if(r==0 && sha[0]){
                Seen *s=seen_find(sha);
                if(s){ g_dupes++; viol = viol?viol:"duplicate";
                    fprintf(stderr,"DUPE: %s == %s\n",full,s->path); }
                else seen_add(sha,full);
            }
            if(st.st_size > g_large_gb*(1L<<30)) viol = viol?viol:"large-asset";
            if(viol) g_viol++;
            db_insert(full,(long)st.st_size,type,sha[0]?sha:"",(long)st.st_mtime,mount,viol);
            if(g_json) fprintf(g_json,
                "{\"path\":%s,\"size\":%ld,\"type\":\"%s\",\"sha256\":\"%s\",\"mount\":\"%s\",\"violation\":%s},\n",
                /*json-escaped path*/ sqlite3_mprintf("\"%q\"",full), (long)st.st_size, type, sha,
                mount, viol?sqlite3_mprintf("\"%q\"",viol):"null");
        }
    }
    closedir(d);
}

/* ---------- ports ---------- */
static int port_open(const char *host,int port,int ms){
    struct addrinfo hints,*res=NULL,*ai;
    memset(&hints,0,sizeof hints); hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    char portstr[16]; snprintf(portstr,sizeof portstr,"%d",port);
    if(getaddrinfo(host,portstr,&hints,&res)!=0) return 0;
    int ok=0, fd=-1;
    for(ai=res;ai;ai=ai->ai_next){
        fd=socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
        if(fd<0) continue;
        fcntl(fd,F_SETFL,O_NONBLOCK);
        int c=connect(fd,ai->ai_addr,(socklen_t)ai->ai_addrlen);
        if(c==0){ ok=1; break; }
        if(c<0 && errno==EINPROGRESS){
            fd_set wf; FD_ZERO(&wf); FD_SET(fd,&wf);
            struct timeval tv; tv.tv_sec=ms/1000; tv.tv_usec=(ms%1000)*1000;
            if(select(fd+1,NULL,&wf,NULL,&tv)>0){ ok=1; break; }
        }
        close(fd); fd=-1;
    }
    if(fd>=0) close(fd);
    if(res) freeaddrinfo(res);
    return ok;
}
static void ports_scan(int *nlisten,int *nconflict){
    *nlisten=0; *nconflict=0;
    for(int i=0;i<NPORTS;i++){
        int open=port_open("127.0.0.1",PORTS[i].port,250);
        if(open){
            (*nlisten)++;
            int conflict = (!PORTS[i].expect) && PORTS[i].port==9090;
            if(conflict) (*nconflict)++;
            printf("  %-16s :%-5d %s\n",PORTS[i].name,PORTS[i].port,
                   open?"LISTENING":"-");
            if(conflict) printf("    !! conflict: %s on 9090 (Snap Prometheus) — move Docker Prometheus to 9091\n",
                                PORTS[i].name);
        }
    }
}

/* ---------- gpu ---------- */
static int gpu_count(void){
    int n=0; DIR *d=opendir("/dev");
    if(d){ struct dirent *e; while((e=readdir(d))){
        if(!strncmp(e->d_name,"nvidia",6) && isdigit((unsigned char)e->d_name[6])) n++; }
        closedir(d); }
    return n;
}

/* ---------- image pipeline ---------- */
static void uuid_new(char out[37]){
    int fd=open("/proc/sys/kernel/random/uuid",O_RDONLY);
    if(fd<0){ snprintf(out,37,"%08lx-%04x-%04x-%04x-%012lx",
        (long)time(NULL),(unsigned)getpid()&0xffff,(unsigned)time(NULL)&0xffff,
        (unsigned)clock()&0xffff,(long)getpid()); return; }
    int n=read(fd,out,36); (void)n; out[36]=0; close(fd);
}
/* strip privacy metadata; rewrite file in place to outpath */
static int img_strip(const char *in,const char *out){
    FILE *f=fopen(in,"rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *buf=malloc(sz>0?sz:1); if(!buf){ fclose(f); return -1; }
    if(fread(buf,1,sz,f)!=(size_t)sz){ fclose(f); free(buf); return -1; }
    fclose(f);
    /* dispatch by magic */
    uint8_t *ob=NULL; long osz=0;
    if(sz>=8 && buf[0]==0x89&&buf[1]=='P'&&buf[2]=='N'&&buf[3]=='G'){
        /* PNG: drop tEXt/zTXt/iTXt */
        if(sz<8){ free(buf); return -1; }
        ob=malloc(sz); memcpy(ob,buf,8); osz=8; long p=8;
        while(p+8<=sz){
            uint32_t len=(buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3];
            char type[5]; memcpy(type,buf+p+4,4); type[4]=0;
            long chunk=12+(long)len;
            if(p+chunk>sz) break;
            if(strcmp(type,"tEXt")&&strcmp(type,"zTXt")&&strcmp(type,"iTXt")&&
               strcmp(type,"tIME")&&strcmp(type,"IHDR")/*keep*/){
                /* copy all except metadata; keep IHDR/data etc */
            }
            if(strcmp(type,"tEXt")&&strcmp(type,"zTXt")&&strcmp(type,"iTXt")&&strcmp(type,"tIME")){
                memcpy(ob+osz,buf+p,chunk); osz+=chunk;
            }
            p+=chunk;
        }
    } else if(sz>=3 && buf[0]==0xFF&&buf[1]==0xD8&&buf[2]==0xFF){
        /* JPEG: drop APPn (0xFFE0..0xFFEF) and COM (0xFFFE) */
        ob=malloc(sz); long p=0;
        if(buf[0]==0xFF&&buf[1]==0xD8){ ob[0]=0xFF; ob[1]=0xD8; osz=2; p=2; }
        while(p+2<=sz){
            if(buf[p]!=0xFF){ p++; continue; }
            uint8_t m=buf[p+1];
            if((m>=0xE0&&m<=0xEF)||m==0xFE){
                if(p+4>sz) break;
                int len=(buf[p+2]<<8)|buf[p+3];
                p += 2+len; continue; /* drop */
            }
            /* copy this marker + segment */
            if(m==0xDA){ /* SOS: copy rest verbatim */
                memcpy(ob+osz,buf+p,sz-p); osz+=sz-p; break;
            }
            if(p+4<=sz){ int len=(buf[p+2]<<8)|buf[p+3];
                if(len<2){ memcpy(ob+osz,buf+p,2); osz+=2; p+=2; continue; }
                memcpy(ob+osz,buf+p,2+len); osz+=2+len; p+=2+len; }
            else { memcpy(ob+osz,buf+p,sz-p); osz+=sz-p; break; }
        }
    } else if(sz>=12 && buf[0]=='R'&&buf[1]=='I'&&buf[2]=='F'&&buf[3]=='F'&&
               buf[8]=='W'&&buf[9]=='E'&&buf[10]=='B'&&buf[11]=='P'){
        /* WebP: drop EXIF / XMP chunks */
        ob=malloc(sz); memcpy(ob,buf,12); osz=12; long p=12;
        while(p+8<=sz){
            char cid[5]; memcpy(cid,buf+p,4); cid[4]=0;
            uint32_t len=(buf[p+4]<<24)|(buf[p+5]<<16)|(buf[p+6]<<8)|buf[p+7];
            long chunk=8+((long)len+1)/2*2; /* padded */
            if(p+chunk>sz) break;
            if(strcmp(cid,"EXIF")&&strcmp(cid,"XMP ")){ memcpy(ob+osz,buf+p,chunk); osz+=chunk; }
            p+=chunk;
        }
    } else { free(buf); return 1; /* unsupported */ }
    FILE *o=fopen(out,"wb"); if(!o){ free(buf); free(ob); return -1; }
    fwrite(ob,1,osz,o); fclose(o);
    free(buf); free(ob);
    return 0;
}
static void img_run(const char *indir,const char *outdir){
    DIR *d=opendir(indir); if(!d){ fprintf(stderr,"opendir %s: %s\n",indir,strerror(errno)); exit(1); }
    mkdir(outdir,0755);
    struct dirent *e;
    while((e=readdir(d))){
        if(!strcmp(e->d_name,".")||!strcmp(e->d_name,"..")) continue;
        char in[PATH_MAXLEN],out[PATH_MAXLEN];
        snprintf(in,sizeof in,"%s/%s",indir,e->d_name);
        struct stat st; if(stat(in,&st)!=0||!S_ISREG(st.st_mode)) continue;
        const char *t=classify(in);
        if(strcmp(t,"image")) continue;
        char uuid[37]; uuid_new(uuid);
        const char *ext=strrchr(e->d_name,'.'); if(!ext) ext="";
        snprintf(out,sizeof out,"%s/%s%s",outdir,uuid,ext);
        int r=img_strip(in,out);
        printf("  %-40s -> %s %s\n",e->d_name, basename_of(out), r? (r==1?"(unsupported)":"(ERR)"):"(scrubbed)");
    }
    closedir(d);
}

/* ---------- CLI ---------- */
static void usage(void){
    fprintf(stderr,
      "labsentry - sovereign AI-lab auditor + image pipeline\n"
      "  labsentry scan  --roots A:B:C --db audit.db [--json r.json] [--maxhash MB] [--maxdepth N] [--large-gb N]\n"
      "  labsentry ports\n"
      "  labsentry gpu\n"
      "  labsentry doctor --roots A:B:C [--db audit.db]\n"
      "  labsentry img --in DIR --out DIR\n");
}
int main(int argc,char **argv){
    if(argc<2){ usage(); return 2; }
    const char *cmd=argv[1];
    if(!strcmp(cmd,"scan")||!strcmp(cmd,"doctor")){
        const char *roots=NULL,*db="audit.db",*json=NULL;
        for(int i=2;i<argc;i++){
            if(!strcmp(argv[i],"--roots")&&i+1<argc) roots=argv[++i];
            else if(!strcmp(argv[i],"--db")&&i+1<argc) db=argv[++i];
            else if(!strcmp(argv[i],"--json")&&i+1<argc) json=argv[++i];
            else if(!strcmp(argv[i],"--maxhash")&&i+1<argc) g_maxhash_mb=atoi(argv[++i]);
            else if(!strcmp(argv[i],"--maxdepth")&&i+1<argc) g_maxdepth=atoi(argv[++i]);
            else if(!strcmp(argv[i],"--large-gb")&&i+1<argc) g_large_gb=atol(argv[++i]);
        }
        if(!roots){ fprintf(stderr,"scan: --roots required (colon-separated)\n"); return 2; }
        db_open(db);
        if(json){ g_json=fopen(json,"w"); if(g_json) fprintf(g_json,"{\"generated\":\"%s\",\"assets\":[\n",now_iso()); }
        /* walk each root */
        char *copy=strdup(roots); char *tok=strtok(copy,":");
        while(tok){ walk(tok,0); tok=strtok(NULL,":"); }
        free(copy);
        if(g_json){ fprintf(g_json,"{}]}\n"); fclose(g_json); }
        int nl,nc; ports_scan(&nl,&nc);
        /* summary */
        printf("\n=== labsentry scan summary ===\n");
        printf("  files scanned : %ld\n", g_count);
        printf("  total bytes   : %.2f GB\n", g_bytes/(1024.0*1024*1024));
        printf("  duplicates    : %ld\n", g_dupes);
        printf("  violations    : %ld\n", g_viol);
        printf("  listening svc : %d (conflicts: %d)\n", nl, nc);
        printf("  gpu visible   : %d\n", gpu_count());
        printf("  catalog       : %s\n", db);
        sqlite3_close(g_db);
        return 0;
    }
    if(!strcmp(cmd,"ports")){
        int nl,nc; printf("ports:\n"); ports_scan(&nl,&nc);
        printf("listening=%d conflicts=%d\n",nl,nc); return 0;
    }
    if(!strcmp(cmd,"gpu")){ printf("gpus=%d\n",gpu_count()); return 0; }
    if(!strcmp(cmd,"img")){
        const char *indir=NULL,*outdir=NULL;
        for(int i=2;i<argc;i++){
            if(!strcmp(argv[i],"--in")&&i+1<argc) indir=argv[++i];
            else if(!strcmp(argv[i],"--out")&&i+1<argc) outdir=argv[++i];
        }
        if(!indir||!outdir){ fprintf(stderr,"img: --in and --out required\n"); return 2; }
        printf("image hygiene: %s -> %s\n",indir,outdir);
        img_run(indir,outdir); return 0;
    }
    if(!strcmp(cmd,"report")){
        const char *jsonp=NULL;
        for(int i=2;i<argc;i++){ if(!strcmp(argv[i],"--json")&&i+1<argc) jsonp=argv[++i]; }
        if(!jsonp){ fprintf(stderr,"report: --json <audit.json> required\n"); return 2; }
        char self[1024]; ssize_t n=readlink("/proc/self/exe",self,sizeof self-1); self[n<0?0:n]=0;
        char dir[1024]; strcpy(dir, self); char *sl=strrchr(dir,'/'); if(sl) *sl=0;
        /* search candidate locations for report.py */
        const char *cands[5];
        char c0[2048], c1[2048], c2[2048], c3[2048];
        snprintf(c0,sizeof c0,"%s/tools/report.py",dir);
        snprintf(c1,sizeof c1,"%s/../share/labsentry/tools/report.py",dir);
        snprintf(c2,sizeof c2,"/usr/local/share/labsentry/tools/report.py");
        snprintf(c3,sizeof c3,"/usr/share/labsentry/tools/report.py");
        cands[0]=c0; cands[1]=c1; cands[2]=c2; cands[3]=c3; cands[4]=NULL;
        const char *py=NULL;
        for(int k=0;cands[k];k++){ if(access(cands[k],R_OK)==0){ py=cands[k]; break; } }
        if(!py){ fprintf(stderr,"report: tools/report.py not found (install labsentry properly)\n"); return 1; }
        char cmd[3072]; snprintf(cmd,sizeof cmd,"python3 %s %s",py,jsonp);
        return system(cmd);
    }
    usage(); return 2;
}
