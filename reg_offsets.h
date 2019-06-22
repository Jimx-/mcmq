#ifndef _REG_OFFSETS_H_
#define _REG_OFFSETS_H_

#define REG_SIZE 8

/* register offsets into stackframe, see stackframe.h */
#define P_STACKBASE 0
#define SEPCREG P_STACKBASE
#define RAREG SEPCREG + REG_SIZE
#define SPREG RAREG + REG_SIZE
#define KERNELSPREG SPREG + REG_SIZE
#define GPREG KERNELSPREG + REG_SIZE
#define TPREG GPREG + REG_SIZE
#define T0REG TPREG + REG_SIZE
#define T1REG T0REG + REG_SIZE
#define T2REG T1REG + REG_SIZE
#define S0REG T2REG + REG_SIZE
#define S1REG S0REG + REG_SIZE
#define A0REG S1REG + REG_SIZE
#define A1REG A0REG + REG_SIZE
#define A2REG A1REG + REG_SIZE
#define A3REG A2REG + REG_SIZE
#define A4REG A3REG + REG_SIZE
#define A5REG A4REG + REG_SIZE
#define A6REG A5REG + REG_SIZE
#define A7REG A6REG + REG_SIZE
#define S2REG A7REG + REG_SIZE
#define S3REG S2REG + REG_SIZE
#define S4REG S3REG + REG_SIZE
#define S5REG S4REG + REG_SIZE
#define S6REG S5REG + REG_SIZE
#define S7REG S6REG + REG_SIZE
#define S8REG S7REG + REG_SIZE
#define S9REG S8REG + REG_SIZE
#define S10REG S9REG + REG_SIZE
#define S11REG S10REG + REG_SIZE
#define T3REG S11REG + REG_SIZE
#define T4REG T3REG + REG_SIZE
#define T5REG T4REG + REG_SIZE
#define T6REG T5REG + REG_SIZE
#define SSTATUSREG T6REG + REG_SIZE
#define SBADADDRREG SSTATUSREG + REG_SIZE
#define SCAUSEREG SBADADDRREG + REG_SIZE

#define P_ORIGA0 SCAUSEREG + REG_SIZE
#define P_CPU P_ORIGA0 + REG_SIZE

#define P_TBR_PHYS P_CPU + REG_SIZE
#define P_TBR_VIR P_TBR_PHYS + REG_SIZE

#endif
