#ifndef _SPINLOCK_H_
#define _SPINLOCK_H_

typedef struct {
    volatile unsigned int lock;
} spinlock_t;

typedef struct {
    volatile unsigned int lock;
} rwlock_t;

#define spin_is_locked(x) (((x)->lock) != 0)

static inline void spin_lock_init(spinlock_t* lock) { lock->lock = 0; }

static inline int spin_trylock(spinlock_t* lock)
{
    int tmp = 1, busy;

    __asm__ __volatile__("	amoswap.w %0, %2, %1\n"
                         "  fence r, rw\n"
                         : "=r"(busy), "+A"(lock->lock)
                         : "r"(tmp)
                         : "memory");

    return !busy;
}

static inline void spin_lock(spinlock_t* lock)
{
    while (1) {
        if (spin_is_locked(lock)) continue;

        if (spin_trylock(lock)) break;
    }
}

static inline void spin_unlock(spinlock_t* lock)
{
    __asm__ __volatile__("fence r, rw" : : : "memory");
    lock->lock = 0;
}

static inline void rwlock_read_lock(rwlock_t* lock)
{
    int tmp;

    __asm__ __volatile__("1:	lr.w	%1, %0\n"
                         "	bltz	%1, 1b\n"
                         "	addi	%1, %1, 1\n"
                         "	sc.w	%1, %1, %0\n"
                         "	bnez	%1, 1b\n"
                         "  fence   r, rw\n"
                         : "+A"(lock->lock), "=&r"(tmp)::"memory");
}

static inline void rwlock_write_lock(rwlock_t* lock)
{
    int tmp;

    __asm__ __volatile__("1:	lr.w	%1, %0\n"
                         "	bnez	%1, 1b\n"
                         "	li	%1, -1\n"
                         "	sc.w	%1, %1, %0\n"
                         "	bnez	%1, 1b\n"
                         "  fence   r, rw\n"
                         : "+A"(lock->lock), "=&r"(tmp)::"memory");
}

static inline int rwlock_read_trylock(rwlock_t* lock)
{
    int busy;

    __asm__ __volatile__("1:	lr.w	%1, %0\n"
                         "	bltz	%1, 1f\n"
                         "	addi	%1, %1, 1\n"
                         "	sc.w	%1, %1, %0\n"
                         "	bnez	%1, 1b\n"
                         "  fence   r, rw\n"
                         "1:\n"
                         : "+A"(lock->lock), "=&r"(busy)::"memory");

    return !busy;
}

static inline int rwlock_write_trylock(rwlock_t* lock)
{
    int busy;

    __asm__ __volatile__("1:	lr.w	%1, %0\n"
                         "	bnez	%1, 1f\n"
                         "	li	%1, -1\n"
                         "	sc.w	%1, %1, %0\n"
                         "	bnez	%1, 1b\n"
                         "  fence   r, rw\n"
                         "1:\n"
                         : "+A"(lock->lock), "=&r"(busy)::"memory");

    return !busy;
}

static inline void rwlock_read_unlock(rwlock_t* lock)
{
    __asm__ __volatile__("  fence   r, rw\n"
                         "	amoadd.w x0, %1, %0\n"
                         : "+A"(lock->lock)
                         : "r"(-1)
                         : "memory");
}

static inline void rwlock_write_unlock(rwlock_t* lock)
{
    __asm__ __volatile__("fence r, rw" : : : "memory");
    lock->lock = 0;
}

#endif
