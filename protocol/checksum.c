#include <stdlib.h>
#include <netinet/in.h>
#include "checksum.h"

#if ( __i386__ || __i386 )

u_short
ipFastCheckSum (u_char *iph, u_int iphLen) {
    u_int sum;

    __asm__ __volatile__(
        "   movl (%1), %0    \n"
        "   subl $4, %2      \n"
        "   jbe 2f           \n"
        "   addl 4(%1), %0   \n"
        "   adcl 8(%1), %0   \n"
        "   adcl 12(%1), %0  \n"
        "1: adcl 16(%1), %0  \n"
        "   lea 4(%1), %1    \n"
        "   decl %2          \n"
        "   jne 1b           \n"
        "   adcl $0, %0      \n"
        "   movl %0, %2      \n"
        "   shrl $16, %0     \n"
        "   addw %w2, %w0    \n"
        "   adcl $0, %0      \n"
        "   notl %0          \n"
        "2:                  \n"
        : "=r" (sum), "=r" (iph), "=r" (iphLen)
        : "1" (iph), "2" (iphLen)
        : "cc");

    return (u_short) sum;
}

static u_int
checkSumPartial (u_char * buff, int len, u_int sum) {
    __asm__ __volatile__(
        "   testl $2, %%esi        \n"
        "   jz 2f                  \n"
        "   subl $2, %%ecx         \n"
        "   jae 1f                 \n"
        "   addl $2, %%ecx         \n"
        "   jmp 4f                 \n"
        "1: movw (%%esi), %%di     \n"
        "   addl $2, %%esi         \n"
        "   addw %%di, %%ax        \n"
        "   adcl $0, %%eax         \n"
        "2:                        \n"
        "   movl %%ecx, %%edx      \n"
        "   shrl $5, %%ecx         \n"
        "   jz 2f                  \n"
        "   testl %%esi, %%esi     \n"
        "1: movl (%%esi), %%edi    \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 4(%%esi), %%edi   \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 8(%%esi), %%edi   \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 12(%%esi), %%edi  \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 16(%%esi), %%edi  \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 20(%%esi), %%edi  \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 24(%%esi), %%edi  \n"
        "   adcl %%edi, %%eax      \n"
        "   movl 28(%%esi), %%edi  \n"
        "   adcl %%edi, %%eax      \n"
        "   lea 32(%%esi), %%esi   \n"
        "   dec %%ecx              \n"
        "   jne 1b                 \n"
        "   adcl $0, %%eax         \n"
        "2: movl %%edx, %%ecx      \n"
        "   andl $0x1c, %%edx      \n"
        "   je 4f                  \n"
        "   shrl $2, %%edx         \n"
        "3: adcl (%%esi), %%eax    \n"
        "   lea 4(%%esi), %%esi    \n"
        "   dec %%edx              \n"
        "   jne 3b                 \n"
        "   adcl $0, %%eax         \n"
        "4: andl $3, %%ecx         \n"
        "   jz 7f                  \n"
        "   cmpl $2, %%ecx         \n"
        "   jb 5f                  \n"
        "   movw (%%esi),%%cx      \n"
        "   leal 2(%%esi),%%esi    \n"
        "   je 6f                  \n"
        "   shll $16,%%ecx         \n"
        "5: movb (%%esi),%%cl      \n"
        "6: addl %%ecx,%%eax       \n"
        "   adcl $0, %%eax         \n"
        "7:                        \n"
        : "=a" (sum), "=c" (len), "=S" (buff)
        : "0" (sum), "1" (len), "2" (buff)
        : "di", "dx" , "cc");

    return sum;
}

static inline u_int
checkSumFold (u_int sum) {
    __asm__ __volatile__(
        "   addl %1, %0      \n"
        "   adcl $0xffff, %0 \n"
        : "=r" (sum)
        : "r" (sum << 16), "0" (sum & 0xffff0000)
        : "cc" );
    return ((~sum) >> 16);
}

static inline u_short
checkSumTcpMagic (u_int saddr, u_int daddr, u_short len, u_short proto, u_int sum) {
    __asm__ __volatile__(
        "   addl %1, %0 \n"
        "   adcl %2, %0 \n"
        "   adcl %3, %0 \n"
        "   adcl $0, %0 \n"
        : "=r" (sum)
        : "g" (daddr), "g" (saddr), "g" ((ntohs (len) << 16) + (proto * 256)), "0" (sum)
        : "cc");
    return (u_short) checkSumFold (sum);
}

u_short
tcpFastCheckSum (u_char *tcph, int tcpLen, u_int saddr, u_int daddr) {
    return checkSumTcpMagic (saddr, daddr, tcpLen, IPPROTO_TCP,
                             checkSumPartial (tcph, tcpLen, 0));
}

#else  /* !i386 */

typedef struct _psuedoHeader psuedoHeader;
typedef psuedoHeader *psuedoHeaderPtr;

struct _psuedoHeader {
    u_int saddr;
    u_int daddr;
    u_char zero;
    u_char protocol;
    u_short len;
};

static u_short
ipCheckExt (register u_short *addr, register u_int len, int addon) {
    register u_int nleft = len;
    register u_short *tmp = addr;
    register int sum = addon;
    u_short answer = 0;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1) {
        sum += *tmp++;
        nleft -= 2;
    }

    /* Mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) tmp;
        sum += answer;
    }

    /* Add back carry outs from top 16 bits to low 16 bits */
    /* add hi 16 to low 16 */
    sum = (sum >> 16) + (sum & 0xffff);
    /* Add carry */
    sum += (sum >> 16);
    /* Truncate to 16 bits */
    answer = ~sum;

    return answer;
}

u_short
ipFastCheckSum (u_char *iph, u_int iphLen) {
    return ipCheckExt ((u_short *) iph, iphLen << 2, 0);
}

u_short
tcpFastCheckSum (u_char *tcph, int tcpLen, u_int saddr, u_int daddr) {
    u_int i;
    psuedoHeader phdr;
    int sum = 0;

    phdr.saddr = saddr;
    phdr.daddr = daddr;
    phdr.zero = 0;
    phdr.protocol = IPPROTO_TCP;
    phdr.len = htons (tcpLen);
    for (i = 0; i < sizeof (psuedoHeader); i += 2) {
        sum += *(u_short *) ((u_char *) (&phdr) + i);
    }

    return ipCheckExt ((u_short *) tcph, tcpLen, sum);
}

#endif  /* !i386 */
