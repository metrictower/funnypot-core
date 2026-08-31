/*
 * FP-0230 — offline collision-blob favicon forge (dev-bench, never shipped on the serve path).
 *
 * Authors a GENERIC, self-drawn 16x16 ICO (a plain geometric ring mark — NO vendor artwork), then
 * brute-forces 6 benign trailing bytes (ICO readers ignore bytes past the image data) until
 *   FaviconHash(bytes) == target_signed_int32   (== mmh3(base64.encodebytes(bytes)), the scanner value).
 *
 * Speed: MurmurHash3 is incremental, so the murmur state over the fixed base64 prefix is precomputed
 * ONCE and each trial only re-mixes the final ~3 blocks + finaliser (~20 ops/trial), so ~2^32 trials
 * run in well under a minute. The bytes are ours; a 32-bit integer is not copyrightable -> clean.
 *
 * The result's murmur is re-verified here AND, independently, by FaviconHash::hash + the KAT in PHP.
 *
 *   cc -O2 -o forge forge.c && ./forge <target_signed_int> [color_rgb_hex] [nonce]
 * prints: the winning file as base64 (one line) to stdout; provenance to stderr.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void put_le16(uint8_t *p, uint16_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; }
static void put_le32(uint8_t *p, uint32_t v) { p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; }

/* Build a 16x16 32bpp ICO with a self-drawn ring (generic geometric mark). Returns total length.
   fixedLen is set to the length up to (but not including) the 6-byte varying tail; we pad so
   fixedLen % 3 == 0 so the 6 varying bytes map to the final 8 base64 chars cleanly. */
static size_t build_icon(uint8_t *out, uint32_t rgb, uint8_t nonce, size_t *fixedLen) {
    const int W = 16, H = 16;
    size_t o = 0;
    /* ICONDIR */
    put_le16(out+o,0); o+=2;              /* reserved */
    put_le16(out+o,1); o+=2;              /* type = icon */
    put_le16(out+o,1); o+=2;              /* count = 1 */
    /* ICONDIRENTRY */
    size_t xorSize = (size_t)W*H*4;
    size_t andSize = (size_t)((W+31)/32)*4*H;   /* 1bpp mask, rows padded to 32 bits */
    size_t imgSize = 40 + xorSize + andSize;
    size_t entryOff = 22;
    out[o++]=W; out[o++]=H; out[o++]=0; out[o++]=0;   /* w,h,colorcount,reserved */
    put_le16(out+o,1); o+=2;              /* planes */
    put_le16(out+o,32); o+=2;             /* bitcount */
    put_le32(out+o,(uint32_t)imgSize); o+=4;
    put_le32(out+o,(uint32_t)entryOff); o+=4;
    /* BITMAPINFOHEADER */
    put_le32(out+o,40); o+=4;
    put_le32(out+o,(uint32_t)W); o+=4;
    put_le32(out+o,(uint32_t)(H*2)); o+=4; /* height doubled (XOR+AND) */
    put_le16(out+o,1); o+=2;
    put_le16(out+o,32); o+=2;
    put_le32(out+o,0); o+=4;              /* BI_RGB */
    put_le32(out+o,(uint32_t)xorSize); o+=4;
    put_le32(out+o,2835); o+=4; put_le32(out+o,2835); o+=4; /* ppm */
    put_le32(out+o,0); o+=4; put_le32(out+o,0); o+=4;
    /* XOR pixel data, BGRA, bottom-up. A centered ring: a plain geometric mark. */
    uint8_t R=(rgb>>16)&0xff, G=(rgb>>8)&0xff, B=rgb&0xff;
    for (int y=0; y<H; y++) {
        int py = H-1-y; /* bottom-up */
        for (int x=0; x<W; x++) {
            double dx = x-7.5, dy = py-7.5, d = dx*dx+dy*dy;
            int on = (d <= 49.0 && d >= 16.0); /* ring: radius ~4..7 */
            if (on) { out[o++]=B; out[o++]=G; out[o++]=R; out[o++]=0xff; }
            else    { out[o++]=0; out[o++]=0; out[o++]=0; out[o++]=0x00; }
        }
    }
    /* AND mask: all zero = "use alpha" (fully drawn from XOR alpha). */
    for (size_t i=0;i<andSize;i++) out[o++]=0;
    /* one provenance/nonce byte in the fixed region so distinct runs explore distinct icons */
    out[o++]=nonce;
    /* pad the FIXED region to a multiple of 3 so the 6 varying bytes = the final 8 base64 chars */
    while (o % 3 != 0) out[o++]=0x00;
    *fixedLen = o;
    /* 6 varying tail bytes (placeholder) */
    for (int i=0;i<6;i++) out[o++]=0;
    return o;
}

/* encodebytes (base64 + '\n' every 76 + trailing '\n' for a final partial line) into out; returns len. */
static size_t encodebytes(const uint8_t *in, size_t n, uint8_t *out) {
    static uint8_t raw[8192];
    size_t r=0,i=0;
    while (i+3<=n){uint32_t v=(in[i]<<16)|(in[i+1]<<8)|in[i+2];raw[r++]=B64[(v>>18)&63];raw[r++]=B64[(v>>12)&63];raw[r++]=B64[(v>>6)&63];raw[r++]=B64[v&63];i+=3;}
    size_t rem=n-i;
    if(rem==1){uint32_t v=in[i]<<16;raw[r++]=B64[(v>>18)&63];raw[r++]=B64[(v>>12)&63];raw[r++]='=';raw[r++]='=';}
    else if(rem==2){uint32_t v=(in[i]<<16)|(in[i+1]<<8);raw[r++]=B64[(v>>18)&63];raw[r++]=B64[(v>>12)&63];raw[r++]=B64[(v>>6)&63];raw[r++]='=';}
    size_t oo=0,col=0;
    for(size_t j=0;j<r;j++){out[oo++]=raw[j];if(++col==76){out[oo++]='\n';col=0;}}
    if(col!=0)out[oo++]='\n';
    return oo;
}

static uint32_t rotl32(uint32_t x,int8_t r){return (x<<r)|(x>>(32-r));}

/* murmur over S[0..B) (B multiple of 4): return h1 accumulator (no tail, no finalize). */
static uint32_t murmur_prefix(const uint8_t *S, size_t B) {
    uint32_t h1=0; size_t nb=B/4;
    for(size_t i=0;i<nb;i++){size_t o=i*4;uint32_t k1=(uint32_t)S[o]|((uint32_t)S[o+1]<<8)|((uint32_t)S[o+2]<<16)|((uint32_t)S[o+3]<<24);
        k1*=0xcc9e2d51;k1=rotl32(k1,15);k1*=0x1b873593;h1^=k1;h1=rotl32(h1,13);h1=h1*5+0xe6546b64;}
    return h1;
}
/* finish murmur from precomputed h1 over the suffix S[B..len) with total length = len. */
static uint32_t murmur_finish(uint32_t h1, const uint8_t *S, size_t B, size_t len) {
    size_t nb=len/4;
    for(size_t i=B/4;i<nb;i++){size_t o=i*4;uint32_t k1=(uint32_t)S[o]|((uint32_t)S[o+1]<<8)|((uint32_t)S[o+2]<<16)|((uint32_t)S[o+3]<<24);
        k1*=0xcc9e2d51;k1=rotl32(k1,15);k1*=0x1b873593;h1^=k1;h1=rotl32(h1,13);h1=h1*5+0xe6546b64;}
    const uint8_t *t=S+nb*4;uint32_t k1=0;
    switch(len&3){case 3:k1^=(uint32_t)t[2]<<16;case 2:k1^=(uint32_t)t[1]<<8;case 1:k1^=(uint32_t)t[0];k1*=0xcc9e2d51;k1=rotl32(k1,15);k1*=0x1b873593;h1^=k1;}
    h1^=(uint32_t)len;h1^=h1>>16;h1*=0x85ebca6b;h1^=h1>>13;h1*=0xc2b2ae35;h1^=h1>>16;return h1;
}

/* emit standard (unwrapped) base64 of a raw file to stdout */
static void emit_b64(const uint8_t *icon, size_t iconLen) {
    size_t i=0;
    while(i+3<=iconLen){uint32_t v=(icon[i]<<16)|(icon[i+1]<<8)|icon[i+2];putchar(B64[(v>>18)&63]);putchar(B64[(v>>12)&63]);putchar(B64[(v>>6)&63]);putchar(B64[v&63]);i+=3;}
    size_t rem=iconLen-i;
    if(rem==1){uint32_t v=icon[i]<<16;putchar(B64[(v>>18)&63]);putchar(B64[(v>>12)&63]);putchar('=');putchar('=');}
    else if(rem==2){uint32_t v=(icon[i]<<16)|(icon[i+1]<<8);putchar(B64[(v>>18)&63]);putchar(B64[(v>>12)&63]);putchar(B64[(v>>6)&63]);putchar('=');}
    putchar('\n');
}

int main(int argc,char**argv){
    if(argc<2){fprintf(stderr,"usage: forge <target_signed_int> [rgb_hex] [nonce]  |  forge neutral [rgb_hex] [nonce]\n");return 2;}
    /* neutral: no target — build a plain generic icon and emit it (caller checks its hash is not a
       known product signature). The 6 tail bytes are a fixed nonce pattern, not a collision search. */
    if(strcmp(argv[1],"neutral")==0){
        uint32_t rgb = argc>2 ? (uint32_t)strtoul(argv[2],NULL,16) : 0x808A93;
        uint8_t nonce = argc>3 ? (uint8_t)strtoul(argv[3],NULL,10) : 7;
        uint8_t icon[8192]; size_t fixedLen;
        size_t iconLen = build_icon(icon, rgb, nonce, &fixedLen);
        for(int i=0;i<6;i++) icon[fixedLen+i]=(uint8_t)(0x5A ^ i);
        emit_b64(icon, iconLen);
        fprintf(stderr,"NEUTRAL iconLen=%zu rgb=%06x nonce=%u\n",iconLen,rgb,nonce);
        return 0;
    }
    int32_t target=(int32_t)strtol(argv[1],NULL,10);
    uint32_t rgb = argc>2 ? (uint32_t)strtoul(argv[2],NULL,16) : 0x3B7DD8;
    uint8_t nonce = argc>3 ? (uint8_t)strtoul(argv[3],NULL,10) : 0;

    uint8_t icon[8192]; size_t fixedLen;
    size_t iconLen = build_icon(icon, rgb, nonce, &fixedLen);

    /* Encode once to map the 6 varying bytes -> 8 final base64 chars and to precompute the prefix. */
    uint8_t S[16384];
    /* set varying bytes to 0 then to 0xFF to locate the differing char positions */
    for(int i=0;i<6;i++) icon[fixedLen+i]=0x00;
    size_t Slen = encodebytes(icon, iconLen, S);
    uint8_t S1[16384]; uint8_t icon1[8192]; memcpy(icon1,icon,iconLen);
    for(int i=0;i<6;i++) icon1[fixedLen+i]=0xFF;
    size_t S1len = encodebytes(icon1, iconLen, S1);
    if(S1len!=Slen){fprintf(stderr,"length changed under tail variation\n");return 3;}
    /* varying positions = where S and S1 differ */
    int vpos[16]; int nv=0;
    for(size_t i=0;i<Slen;i++){ if(S[i]!=S1[i]){ if(nv<16) vpos[nv]=(int)i; nv++; } }
    if(nv!=8){fprintf(stderr,"expected 8 varying base64 chars, got %d\n",nv);return 3;}
    size_t firstV=vpos[0];
    size_t Bblk=(firstV/4)*4;
    uint32_t h1base=murmur_prefix(S,Bblk);

    /* iterate 6 varying bytes; encode -> 8 chars written at vpos; continue murmur. */
    uint64_t tries=0; uint64_t cap=(uint64_t)1<<34; /* generous headroom over 2^32 */
    for(uint64_t c=0;c<cap;c++){
        uint8_t vb[6];
        vb[0]=(c)&0xff; vb[1]=(c>>8)&0xff; vb[2]=(c>>16)&0xff; vb[3]=(c>>24)&0xff; vb[4]=(c>>32)&0xff; vb[5]=(c>>40)&0xff;
        /* encode the 6 bytes into 8 base64 chars (two 3->4 groups), write at vpos */
        uint32_t g0=(vb[0]<<16)|(vb[1]<<8)|vb[2];
        uint32_t g1=(vb[3]<<16)|(vb[4]<<8)|vb[5];
        S[vpos[0]]=B64[(g0>>18)&63];S[vpos[1]]=B64[(g0>>12)&63];S[vpos[2]]=B64[(g0>>6)&63];S[vpos[3]]=B64[g0&63];
        S[vpos[4]]=B64[(g1>>18)&63];S[vpos[5]]=B64[(g1>>12)&63];S[vpos[6]]=B64[(g1>>6)&63];S[vpos[7]]=B64[g1&63];
        uint32_t h=murmur_finish(h1base,S,Bblk,Slen);
        tries++;
        if((int32_t)h==target){
            /* write winning bytes into icon and emit as base64 */
            memcpy(icon+fixedLen, vb, 6);
            /* verify full recompute */
            uint8_t V[16384]; size_t Vlen=encodebytes(icon,iconLen,V);
            uint32_t full=murmur_finish(murmur_prefix(V,0),V,0,Vlen);
            if((int32_t)full!=target){fprintf(stderr,"VERIFY FAILED\n");return 4;}
            /* emit standard base64 (single line, no wrap) of the raw file for the template */
            static const char *b=B64; size_t i=0;
            while(i+3<=iconLen){uint32_t v=(icon[i]<<16)|(icon[i+1]<<8)|icon[i+2];putchar(b[(v>>18)&63]);putchar(b[(v>>12)&63]);putchar(b[(v>>6)&63]);putchar(b[v&63]);i+=3;}
            size_t rem=iconLen-i;
            if(rem==1){uint32_t v=icon[i]<<16;putchar(b[(v>>18)&63]);putchar(b[(v>>12)&63]);putchar('=');putchar('=');}
            else if(rem==2){uint32_t v=(icon[i]<<16)|(icon[i+1]<<8);putchar(b[(v>>18)&63]);putchar(b[(v>>12)&63]);putchar(b[(v>>6)&63]);putchar('=');}
            putchar('\n');
            fprintf(stderr,"FORGED target=%d tries=%llu iconLen=%zu rgb=%06x nonce=%u\n",
                    target,(unsigned long long)tries,iconLen,rgb,nonce);
            return 0;
        }
    }
    fprintf(stderr,"NOT FOUND within cap (%llu tries)\n",(unsigned long long)tries);
    return 1;
}
