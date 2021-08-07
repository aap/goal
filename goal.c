#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>

typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef uintptr_t uptr;
#define nil NULL

typedef struct kheapinfo kheapinfo;
struct kheapinfo
{
	uptr base;
	uptr top;
	uptr cur;
	uptr top_base;
};

#define ALLOC_ZERO 0x1000
#define ALLOC_TOP 0x2000

#define ALIGN(n, a) ((n + (a)-1) & ~((a)-1))
#define PTRSZ (sizeof(void*))

kheapinfo _globalheap;
kheapinfo *kglobalheap = &_globalheap;
kheapinfo _debugheap;
kheapinfo *kdebugheap = &_debugheap;
// not original
kheapinfo _codeheap;
kheapinfo *kcodeheap = &_codeheap;

typedef union symbol symbol;
union symbol
{
	uptr integ;
	void *ptr;
};

typedef struct gstring gstring;
struct gstring
{
	u32 len;
	char cstr[1];	// actually [len+1]
};

typedef struct symname symname;
struct symname
{
	u32 hash;
	gstring *gstr;
};

typedef struct type type;
struct type
{
	symbol *sym;
	type *parent;
	u16 size, size_aligned;
	u16 heap_base, allocated_length;
	// after that the virtuals
};

/* 64 bits */
#define IS_BINT(obj) (((uptr)(obj) & 0xF) == 0)
#define IS_PAIR(obj) (((uptr)(obj) & 0xF) == 4)
#define IS_HEAP_OBJ(obj) (((uptr)(obj) & 0xF) == 8)
#define PAIR(ptr) ((uptr)(ptr) + 4)
#define CAR(pair) (*(uptr*)((uptr)(pair)-4))
#define CDR(pair) (*(uptr*)((uptr)(pair)+4))

#define TYPE_SIZE(info) ((info)&0xFFFF)
#define TYPE_HEAP_BASE(info) (((info)>>16)&0xFFFF)
#define TYPE_ALLOC_LEN(info) (((info)>>32)&0xFFFF)

#define TYPEINFO(l,b,s) ((uptr)(l)<<32 | (uptr)(b)<<16 | (uptr)(s))

enum {
	VIRT_NEW,
	VIRT_DELETE,
	VIRT_PRINT,
	VIRT_INSPECT,
	VIRT_UNKNOWN4,
	VIRT_ASIZE,
	VIRT_COPY,
	VIRT_UNKNOWN7,
	VIRT_UNKNOWN8
};

#define VTAB(val) ((uptr*)((type*)(val)+1))

// This assumes 32 bit pointers :/
// Since symbols are addressed with a 16 bit offset from s7,
// the sym table is split into an upper and lower half
// which together make up 64kb.
// In addition there is a string table which takes another 64k
#define MAX_SYMBOLS (0x10000 / 8)
#define LAST_SYMBOL (MAX_SYMBOLS-32)
int NumSymbols;

symbol *SymbolTable;
symbol *SymbolTable2;
symbol *LastSymbol;

#define EMPTY PAIR(SymbolTable-3)

#define ID_OFF(symid) ((symid)*2*PTRSZ)

#define OBJ_TYPE(obj) (((uptr*)(obj))[-1])
#define OBJ_TYPEPTR(obj) ((type*)(((uptr*)(obj))[-1]))

#define SYM_O(offset) ((symbol*)((uptr)SymbolTable + (offset)))
#define SYMPTR_O(offset) ((uptr)SYM_O(offset))
#define SYMVALPTR_O(offset) (SYM_O(offset)->ptr)
#define SYMVALINT_O(offset) (SYM_O(offset)->integ)

#define SYM(symid) SYM_O(ID_OFF(symid))
#define SYMPTR(symid) SYMPTR_O(ID_OFF(symid))
#define SYMVALPTR(symid) SYMVALPTR_O(ID_OFF(symid))
#define SYMVALINT(symid) SYMVALINT_O(ID_OFF(symid))

// what are these 13 pointers?
#define SYMNAME(sym)  ((symname*)(((symbol*)sym) + 2*LAST_SYMBOL + 13))
#define SYMHASH(sym) (((symname*)(((symbol*)sym) + 2*LAST_SYMBOL + 13))->hash)
#define SYMSTR(sym)  (((symname*)(((symbol*)sym) + 2*LAST_SYMBOL + 13))->gstr->cstr)

enum Symbols
{
	sym_false,	// 0
	sym_true,	// 8
	sym_function,	// 16
	sym_basic,	// 24
	sym_string,	// 32
	sym_symbol,	// 40
	sym_type,	// 48
	sym_object,	// 56
	sym_link_block,	// 64
	sym_integer,	// 72
	sym_sinteger,	// 80
	sym_uinteger,	// 88
	sym_binteger,	// 96
	sym_int8,	// 104
	sym_int16,	// 112
	sym_int32,	// 120
	sym_int64,	// 128
	sym_int128,	// 136
	sym_uint8,	// 144
	sym_uint16,	// 152
	sym_uint32,	// 150
	sym_uint64,	// 168
	sym_uint128,	// 176
	sym_float,	// 184
	sym_process_tree,	// 192
	sym_process,	// 200
	sym_thread,	// 208
	sym_structure,	// 216
	sym_pair,	// 224
	sym_pointer,	// 232
	sym_number,	// 240
	sym_array,	// 248
	sym_vu_function,	// 256
	sym_connectable,	// 264
	sym_stack_frame,	// 272
	sym_file_stream,	// 280
	sym_kheap,	// 288
	sym_nothing,	// 296
	sym_delete_basic,	// 304
	sym_static,	// 312
	sym_global,	// 320
	sym_debug,	// 328
	sym_loading_level,	// 336
	sym_loading_package,	// 344
	sym_process_level_heap,	// 352
	sym_stack,	// 360
	sym_scratch,	// 368
	sym_scratch_top,	// 376
	sym_zero_func,	// 384
	sym_asize_of_basic_func,	// 392
	sym_copy_basic_func,	// 400
	sym_level,	// 408
	sym_art_group,	// 416
	sym_texture_page_dir,	// 424
	sym_texture_page,	// 432
	sym_sound,	// 440
	sym_dgo,	// 448
	sym_top_level,	// 456

	sym_code,	// mine

	NUM_FIXED_SYMS
};

u32 crc_table[256];

void
init_crc(void)
{
	u32 i, j;
	u32 n;
	for(i = 0; i < 256; i++) {
		n = i<<24;
		for(j = 0; j < 8; j++)
			if(n & 0x80000000) {
				n = n*2;
				n ^= 0x4C11DB7;
			} else
				n *= 2;
		crc_table[i] = n;
	}
}

u32
crc32(u8 *str, int len)
{
	u32 crc;
	crc = 0;
	while(len--)
		crc = (crc<<8 | *str++) ^ crc_table[crc>>24];
	return ~crc;
}

void
kinitheap(kheapinfo *heap, void *mem, size_t size)
{
	heap->base = (uptr)mem;
	heap->cur = heap->base;
	heap->top = heap->base + size;
	heap->top_base = heap->top;
	memset(mem, 0, size);
}

int
kheapused(kheapinfo *heap)
{
	return heap->cur - heap->base;
}

void
kheapstatus(kheapinfo *heap)
{
	printf("[%8p] kheap\n\tbase: %p\n\ttop-base: %p\n\tcur: %p\n\ttop: %p\n",
		heap, heap->base, heap->top_base, heap->cur, heap->top);
	printf("\t used bot: %d of %d bytes\n\t used top: %d of %d bytes\n\t symbols: %d of %d\n",
		heap->cur - heap->base,
		heap->top_base - heap->base,
		heap->top_base - heap->top,
		heap->top_base - heap->base,
		NumSymbols, MAX_SYMBOLS);
}

void*
kmalloc(kheapinfo *heap, size_t size, u32 flags, const char *name)
{
	u32 align;
	uptr ptr;

	align = flags & 0xFFF;
	if(heap == nil)
		heap = kglobalheap;

	if(flags & ALLOC_TOP) {
		ptr = heap->top - size;
		if(align == 0)
			align = 16;
		ptr &= ~(uptr)align + 1;
		if(size == 0)
			return (void*)ptr;
		if(heap->cur >= ptr) {
			printf("kmalloc; !alloc mem from top %s (%d bytes) heap %p\n",
				name, size, heap);
			kheapstatus(heap);
			return nil;
		}
		heap->top = ptr;
	} else {
		ptr = heap->cur;
		if(align == 0x40)
			ptr = (ptr+0x3F) & ~0x3Full;
		else if(align == 0x100)
			ptr = (ptr+0xFF) & ~0xFFull;
		else
			ptr = (ptr+0xF) & ~0xFull;
		if(size == 0)
			return (void*)ptr;
		if(ptr + size >= heap->top) {
			printf("kmalloc; !alloc mem %s (%d bytes) heap %p\n",
				name, size, heap);
			kheapstatus(heap);
			return nil;
		}
		heap->cur = ptr + size;
	}
	if(flags & ALLOC_ZERO)
		memset((void*)ptr, 0, size);
	return (void*)ptr;
}

void
kfree(void *ptr)
{
}

void*
alloc_from_heap(uptr heap, uptr type, size_t size)
{
	void *mem;
	if(heap == SYMPTR(sym_global) ||
	   heap == SYMPTR(sym_debug) ||
	   heap == SYMPTR(sym_code) ||			// mine
	   heap == SYMPTR(sym_loading_level) ||
	   heap == SYMPTR(sym_process_level_heap)) {
		symbol *typesym = (symbol*)type;
		char *name = "global-object";
		if(typesym && typesym->ptr && SYMNAME(typesym)->gstr)
			name = SYMSTR(typesym);
		mem = kmalloc(((symbol*)heap)->ptr, size, ALLOC_ZERO, name);
	} else if(heap == SYMPTR(sym_process)) {
		// TODO
		mem = nil;
	} else if(heap == SYMPTR(sym_scratch)) {
		mem = SYMVALPTR(sym_scratch_top);
		SYMVALINT(sym_scratch_top) += size;
		memset(mem, 0, size);
	} else {
		mem = (void*)heap;
		memset(mem, 0, size);
	}
	return mem;
}

/* Heap objects have their type in the word before the pointer
 * that means the pointer returned will be at offset 4 or 8 */
void*
alloc_heap_object(uptr heap, uptr type, size_t size)
{
	uptr *mem;
	mem = alloc_from_heap(heap, type, size);
	if(mem == nil)
		return nil;
	*mem = type;
	return mem+1;
	
}

gstring*
make_string_from_c(char *cstr)
{
	int len, alloclen;
	gstring *gstr;

	len = strlen(cstr);
	alloclen = len + 1;
	// ????? not even sure if sizeof is right
	if(alloclen < sizeof(gstring))
		alloclen = sizeof(gstring);
	gstr = alloc_heap_object(SYMPTR(sym_global), SYMVALINT(sym_string),
		PTRSZ+sizeof(gstring)+alloclen);
	gstr->len = len;
	strcpy(gstr->cstr, cstr);
	return gstr;
}

#define TYPESIZE(nmethods) ALIGN(PTRSZ + sizeof(type) + PTRSZ*(nmethods), 16)

void*
alloc_and_init_type(symbol *sym, int nmethods)
{
	sym->ptr = alloc_heap_object(SYMPTR(sym_global), SYMVALINT(sym_type), TYPESIZE(nmethods));
	return sym->ptr;
}

symbol *symbol_slot;

symbol*
find_symbol_in_fixed_area(u32 hash, char *name)
{
	int i;
	for(i = 0; i < NUM_FIXED_SYMS; i++) {
		symbol *sym = SYM(i);
		if(SYMHASH(sym) == hash && strcmp(SYMSTR(sym), name) == 0)
			return sym;
	}
	return nil;
}

symbol*
find_symbol_in_area(u32 hash, char *name, symbol *start, symbol *end)
{
	symbol *sym;
	for(sym = start; sym < end; sym += 2) {	// gotta skip type too
		if(SYMHASH(sym) == hash && strcmp(SYMSTR(sym), name) == 0)
			return sym;
		if(SYMHASH(sym) == 0) {
			symbol_slot = sym;
			return find_symbol_in_fixed_area(hash, name);
		}
	}
	return (symbol*)1;
}

symbol*
find_symbol_from_c(char *name)
{
	u32 hash;
	symbol *sym;

	symbol_slot = nil;
	hash = crc32(name, strlen(name));
	if(hash == 0x8454B6E6 && strcmp(name, "_empty_") == 0)
		return (symbol*)EMPTY;	// TODO: maybe change types
//	original but too platform specific
//	i16 offset = hash*8;
	int offset = hash % MAX_SYMBOLS;
	offset -= MAX_SYMBOLS/2;
	if(offset < 0) {
		sym = find_symbol_in_area(hash, name, SYM(offset), SYM(-2));
		if(sym != (symbol*)1)
			return sym;
		sym = find_symbol_in_area(hash, name, SYM(NUM_FIXED_SYMS), LastSymbol);
		if(sym != (symbol*)1)
			return sym;
	} else {
		sym = find_symbol_in_area(hash, name, SYM(offset), LastSymbol);
		if(sym != (symbol*)1)
			return sym;
		sym = find_symbol_in_area(hash, name, SymbolTable2, SYM(-2));
		if(sym != (symbol*)1)
			return sym;
	}
	return find_symbol_in_fixed_area(hash, name);
}

symbol*
intern_from_c(char *name)
{
	symbol *sym;
	sym = find_symbol_from_c(name);
	if(sym == nil) {
		// insert new symbol
		assert(symbol_slot);
		sym = symbol_slot;
		OBJ_TYPE(sym) = SYMPTR(sym_symbol);
		SYMNAME(sym)->gstr = make_string_from_c(name);
		SYMNAME(sym)->hash = crc32(name, strlen(name));
		NumSymbols++;
	}
	return sym;
}

type*
set_type_values(type *t, type *parent, u64 info)
{
	t->parent = parent;
	t->size = TYPE_SIZE(info);
	t->heap_base = TYPE_HEAP_BASE(info);
	t->size_aligned = ALIGN(t->size, 16);
	if(t->allocated_length < TYPE_ALLOC_LEN(info))
		t->allocated_length = TYPE_ALLOC_LEN(info);
	return t;
}

uptr
call_method_of_type(uptr obj, type *t, int method)
{
	if(IS_HEAP_OBJ(obj)) {
		if(OBJ_TYPE(t) == SYMPTR(sym_type))
			return ((uptr (*)(uptr))(VTAB(t)[method]))(obj);
		else
			printf("#<%p has invalid type ptr %p, bad type %p>\n", obj, t, OBJ_TYPE(t));
	} else
		printf("#<%p has invalid type ptr %p>\n", obj, t);
	return obj;
}

type*
intern_type_from_c(char *name, int nmethods)
{
	symbol *sym;
	type *t;

	sym = intern_from_c(name);
	if(sym->ptr) {
		t = sym->ptr;
		if(TYPESIZE(t->allocated_length) < TYPESIZE(nmethods))
			printf("trying to redefine a type '%s' with %d methods "
				"when it had %d, try restarting\n",
				name, nmethods, t->allocated_length);
	} else {
		// what's this??
		if(nmethods == 0)
			nmethods = 12;
		else if(nmethods == 1)
			nmethods = 44;
		t = alloc_and_init_type(sym, nmethods);
		t->sym = sym;
		t->allocated_length = nmethods;
	}
	return t;
}

type*
intern_type(gstring *name, int nmethods)
{
	return intern_type_from_c(name->cstr, nmethods);
}

void
set_fixed_symbol(i32 offset, char *name, uptr value)
{
	symbol *sym;

	sym = SYM_O(offset);
	OBJ_TYPE(sym) = SYMPTR(sym_symbol);
	sym->integ = value;
	SYMNAME(sym)->gstr = make_string_from_c(name);
	SYMNAME(sym)->hash = crc32(name, strlen(name));
	NumSymbols++;
}

void
set_fixed_type(i32 offset, char *name, uptr parent, u64 info, uptr print_func, uptr inspect_func)
{
	symbol *sym;
	type *t;
	uptr *vtab, *pvtab;

	sym = SYM_O(offset);
	OBJ_TYPE(sym) = SYMPTR(sym_symbol);
	SYMNAME(sym)->gstr = make_string_from_c(name);
	SYMNAME(sym)->hash = crc32(name, strlen(name));
	NumSymbols++;

	t = sym->ptr;
	if(t == nil)
		t = alloc_and_init_type(sym, TYPE_ALLOC_LEN(info));
	OBJ_TYPE(t) = SYMPTR(sym_type);
	t->sym = sym;
	set_type_values(t, (type*)parent, info);

	vtab = (uptr*)(t+1);
	pvtab = (uptr*)(parent+1);
	vtab[VIRT_NEW] = pvtab[VIRT_NEW];
	vtab[VIRT_DELETE] = pvtab[VIRT_DELETE];
	if(print_func)
		vtab[VIRT_PRINT] = print_func;
	else
		vtab[VIRT_PRINT] = pvtab[VIRT_PRINT];
	if(inspect_func)
		vtab[VIRT_INSPECT] = inspect_func;
	else
		vtab[VIRT_INSPECT] = pvtab[VIRT_INSPECT];
	vtab[VIRT_UNKNOWN4] = SYMVALINT(sym_zero_func);
	vtab[VIRT_ASIZE] = pvtab[VIRT_ASIZE];
	vtab[VIRT_COPY] = pvtab[VIRT_COPY];
}

/*
 * AMD64 specific code
 */
uptr
make_nothing_func(void)
{
	void *mem;
	static u8 nothing[] = {
		0xc3
	};
	mem = alloc_heap_object(SYMPTR(sym_code), SYMVALINT(sym_function),
		PTRSZ+ALIGN(sizeof(nothing), 16));
	memcpy(mem, nothing, sizeof(nothing));
	return (uptr)mem;
}

uptr
make_zero_func(void)
{
	void *mem;
	static u8 zero[] = {
		0x31, 0xc0,
		0xc3
	};
	mem = alloc_heap_object(SYMPTR(sym_code), SYMVALINT(sym_function),
		PTRSZ+ALIGN(sizeof(zero), 16));
	memcpy(mem, zero, sizeof(zero));
	return (uptr)mem;
}

typedef uptr (*c_func)(void);
uptr
make_function_from_c(uptr (*func)(void))
{
	void *mem;
	static u8 trampoline[] = {
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
		0xff, 0xe0
	};
	mem = alloc_heap_object(SYMPTR(sym_code), SYMVALINT(sym_function),
		PTRSZ+ALIGN(sizeof(trampoline), 16));
	memcpy(mem, trampoline, sizeof(trampoline));
	memcpy(mem+2, &func, PTRSZ);
	return (uptr)mem;
} 
/*
 * end of AMD64 code
 */

void print_object(uptr obj);
void inspect_object(uptr obj);

uptr
new_illegal(uptr heap, type *t)
{
	fprintf(stderr, "illegal attempt to call new method of static object type %s\n", SYMSTR(t->sym));
	return 0;
}

void
delete_illegal(uptr obj)
{
	fprintf(stderr, "illegal attempt to call delete method of static object @ %p\n", obj);
}

uptr
copy_fixed(uptr obj, uptr heap)
{
	return obj;
}

void
print_binteger(u64 i)
{
	printf("%lld", i>>3);
}

void
inspect_binteger(u64 i)
{
	printf("[%llx] boxed-fixnum %lld", i, i>>3);
}


uptr
new_pair(uptr heap, type *t, uptr car, uptr cdr)
{
	uptr *pair;
	pair = alloc_from_heap(heap, (uptr)t, t->size);
	if(pair == nil)
		return 0;
	pair[0] = car;
	pair[1] = cdr;
	return PAIR(pair);
}

void
delete_pair(uptr obj)
{
	// original game subtracts 8???
	kfree(&CAR(obj));
}

void
print_pair(uptr obj)
{
	if(obj == EMPTY)
		printf("()");
	else {
		printf("(");
		while(IS_PAIR(obj)) {
			print_object(CAR(obj));
			obj = CDR(obj);
			if(obj == EMPTY) {
				printf(")");
				return;
			}
			printf(" ");
		}
		printf(". ");
		print_object(obj);
		printf(")");
	}
}

void
inspect_pair(uptr obj)
{
	printf("[%p] pair ", obj);
	print_pair(obj);
	printf("\n");
}

void
print_object(uptr obj)
{
	if(IS_BINT(obj))
		print_binteger(obj);
	else if(IS_PAIR(obj))
		print_pair(obj);
	else if(IS_HEAP_OBJ(obj))
		call_method_of_type(obj, OBJ_TYPEPTR(obj), VIRT_PRINT);
	else
		printf("#<unknown type %d @ %p>", obj & 0xF);
}

void
inspect_object(uptr obj)
{
	if(IS_BINT(obj))
		inspect_binteger(obj);
	else if(IS_PAIR(obj))
		inspect_pair(obj);
	else if(IS_HEAP_OBJ(obj))
		call_method_of_type(obj, OBJ_TYPEPTR(obj), VIRT_INSPECT);
	else
		printf("#<unknown type %d @ %p>", obj & 0xF);
}

uptr
new_structure(uptr heap, type *t)
{
	return (uptr)alloc_from_heap(heap, (uptr)t, t->size);
}

void
delete_structure(uptr obj)
{
	kfree((void*)obj);
}

void
print_structure(uptr obj)
{
	printf("#<structure @ %p>", obj);
}

void
inspect_structure(uptr obj)
{
	printf("[%p] structure\n", obj);
}

uptr
new_basic(uptr heap, type *t)
{
	return (uptr)alloc_heap_object(heap, (uptr)t, t->size);
}

uptr
asize_of_basic(uptr obj)
{
	return OBJ_TYPEPTR(obj)->size;
}

void
print_basic(uptr obj)
{
	if(IS_HEAP_OBJ(obj)) {
		type *t = (type*)OBJ_TYPE(obj);
		printf("#<%s @ %p>", SYMSTR(t->sym), obj);
	} else
		printf("#<invalid basic %p>\n", obj);
}

void
inspect_basic(uptr obj)
{
	if(IS_HEAP_OBJ(obj)) {
		printf("[%p] ", obj);
		print_object(OBJ_TYPE(obj));
		printf("\n");
	} else
		printf("#<invalid basic %p>\n", obj);
}

uptr
copy_basic(uptr obj, uptr dst)
{
	void *newobj;
	u32 sz;
	sz = call_method_of_type(obj, OBJ_TYPEPTR(obj), VIRT_ASIZE);
	if(OBJ_TYPE(dst) == SYMVALINT(sym_symbol)) {
		newobj = alloc_heap_object(dst, OBJ_TYPE(obj), sz);
		memcpy(newobj, (void*)obj, sz-PTRSZ);
		return (uptr)newobj;
	} else {
		memcpy(&OBJ_TYPE(dst), &OBJ_TYPE(obj), sz);
		return dst;
	}
}

void
delete_basic(uptr obj)
{
	kfree(&OBJ_TYPE(obj));
}

void
print_symbol(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_symbol)) {
		symbol *sym = (symbol*)obj;
		printf("%s", SYMSTR(sym));
	} else
		printf("#<invalid symbol %p>\n", obj);
}

void
inspect_symbol(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_symbol)) {
		symbol *sym = (symbol*)obj;
		printf("[%p] symbol\n\tname: %s\n\thash: %x\n\tvalue: ",
			sym, SYMSTR(sym), SYMNAME(sym)->hash);
		printf("\n");
	} else
		printf("#<invalid symbol %p>\n", obj);
}

uptr
new_type(symbol *sym, type *parent, u64 info)
{
	type *t;
	int i, nmethods;

	nmethods = TYPE_ALLOC_LEN(info);
	// this again?
	if(nmethods == 0)
		nmethods = 12;
	t = intern_type(SYMNAME(sym)->gstr, nmethods);
	for(i = 0; i < nmethods; i++)
		VTAB(t)[i] = VTAB(parent)[i];
	return (uptr)set_type_values(t, parent, info);
}

void
print_type(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_type)) {
		type *t = (type*)obj;
		printf("%s", SYMSTR(t->sym));
	} else
		printf("#<invalid type %p>\n", obj);
}

void
inspect_type(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_type)) {
		type *t = (type*)obj;
		printf("[%p] type\n\tname: %s\n\tparent: ", obj, SYMSTR(t->sym));
		print_object((uptr)t->parent);
		printf("\n\tsize: %d/%d\n\theap-base: %d\n\tallocated_length: %d\n\tprint: ",
			t->size, t->size_aligned,
			t->heap_base, t->allocated_length);
		print_object(VTAB(t)[VIRT_PRINT]);
		printf("\n\tinspect: ");
		print_object(VTAB(t)[VIRT_INSPECT]);
		printf("\n");
	} else
		printf("#<invalid type %p>\n", obj);
}

void
print_string(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_string)) {
		gstring *s = (gstring*)obj;
		printf("\"%s\"", s->cstr);
	} else
		printf("#<invalid string %p>", obj);
}

void
inspect_string(uptr obj)
{
	if(IS_HEAP_OBJ(obj) && OBJ_TYPE(obj) == SYMPTR(sym_string)) {
		gstring *s = (gstring*)obj;
		printf("[%p] string\n\tallocated_length: %\n\tdata: \"%s\"\n",
			obj, s->len, s->cstr);
	} else
		printf("#<invalid string %p>\n", obj);
}

void
print_function(uptr obj)
{
	printf("#<compiled %s @ %p>", SYMSTR(OBJ_TYPEPTR(obj)->sym));
}

void
InitHeapAndSymbol(void)
{
	// NB: two pointers per symbol because of type at [-1]
	symbol *symtab = kmalloc(kglobalheap, MAX_SYMBOLS*(2*PTRSZ)*2, ALLOC_ZERO, "symbol-table");
	SymbolTable2 = symtab + 1;
	SymbolTable = SymbolTable2 + MAX_SYMBOLS;
	LastSymbol = SymbolTable2 + LAST_SYMBOL*2;
	NumSymbols = 0;

	CAR(EMPTY) = EMPTY;
	CDR(EMPTY) = EMPTY;

	SYMVALPTR(sym_global) = kglobalheap;
	alloc_and_init_type(SYM(sym_type), 9);
	alloc_and_init_type(SYM(sym_symbol), 9);
	alloc_and_init_type(SYM(sym_string), 9);
	alloc_and_init_type(SYM(sym_function), 9);

	set_fixed_symbol(ID_OFF(sym_code), "code", (uptr)kcodeheap);		// mine
	set_fixed_symbol(ID_OFF(sym_false), "#f", SYMPTR(sym_false));
	set_fixed_symbol(ID_OFF(sym_true), "#t", SYMPTR(sym_true));
	set_fixed_symbol(ID_OFF(sym_nothing), "nothing", make_nothing_func());
	set_fixed_symbol(ID_OFF(sym_zero_func), "zero-func", make_zero_func());
	set_fixed_symbol(ID_OFF(sym_asize_of_basic_func), "asize-of-basic-func",
		make_function_from_c((c_func)asize_of_basic));
	set_fixed_symbol(ID_OFF(sym_copy_basic_func), "copy-basic-func",	// wrong symbol in original code
		make_function_from_c((c_func)copy_basic));
	set_fixed_symbol(ID_OFF(sym_delete_basic), "delete-basic",
		make_function_from_c((c_func)delete_basic));
	set_fixed_symbol(ID_OFF(sym_global), "global", (uptr)kglobalheap);
	set_fixed_symbol(ID_OFF(sym_debug), "debug", (uptr)kdebugheap);
	set_fixed_symbol(ID_OFF(sym_static), "static", SYMPTR(sym_static));
	set_fixed_symbol(ID_OFF(sym_loading_level), "loading-level", (uptr)kglobalheap);
	set_fixed_symbol(ID_OFF(sym_loading_package), "loading-package", (uptr)kglobalheap);
	set_fixed_symbol(ID_OFF(sym_process_level_heap), "process-level-heap", (uptr)kglobalheap);
	set_fixed_symbol(ID_OFF(sym_stack), "stack", SYMPTR(sym_stack));
	set_fixed_symbol(ID_OFF(sym_scratch), "stack", SYMPTR(sym_scratch));
	set_fixed_symbol(ID_OFF(sym_scratch_top), "*scratch-top*", 0x70000000);
	set_fixed_symbol(ID_OFF(sym_level), "level", 0);
	set_fixed_symbol(ID_OFF(sym_art_group), "art-group", 0);
	set_fixed_symbol(ID_OFF(sym_texture_page_dir), "texture-page-dir", 0);
	set_fixed_symbol(ID_OFF(sym_texture_page), "texture-page", 0);
	set_fixed_symbol(ID_OFF(sym_sound), "sound", 0);
	set_fixed_symbol(ID_OFF(sym_dgo), "dgo", 0);
	set_fixed_symbol(ID_OFF(sym_top_level), "top-level", SYMVALINT(sym_nothing));

	uptr def_new = make_function_from_c((c_func)new_illegal);
	uptr def_del = make_function_from_c((c_func)delete_illegal);

	// Everything derives from object
	set_fixed_type(ID_OFF(sym_object), "object", SYMPTR(sym_object), TYPEINFO(9,0,PTRSZ),
		make_function_from_c((c_func)print_object),
		make_function_from_c((c_func)inspect_object));
	VTAB(SYMVALPTR(sym_object))[VIRT_NEW] = SYMVALINT(sym_nothing);
	VTAB(SYMVALPTR(sym_object))[VIRT_DELETE] = def_del;
	VTAB(SYMVALPTR(sym_object))[VIRT_ASIZE] = SYMVALINT(sym_zero_func);
	VTAB(SYMVALPTR(sym_object))[VIRT_COPY] = make_function_from_c((c_func)copy_fixed);

	// A structure is raw data without a type tag
	set_fixed_type(ID_OFF(sym_structure), "structure", SYMPTR(sym_object), TYPEINFO(9,0,PTRSZ),
		make_function_from_c((c_func)print_structure),
		make_function_from_c((c_func)inspect_structure));
	VTAB(SYMVALPTR(sym_structure))[VIRT_NEW] = make_function_from_c((c_func)new_structure);
	VTAB(SYMVALPTR(sym_structure))[VIRT_DELETE] = make_function_from_c((c_func)delete_structure);

	// A basic is a heap object with type tag
	set_fixed_type(ID_OFF(sym_basic), "basic", SYMPTR(sym_structure), TYPEINFO(9,0,PTRSZ),
		make_function_from_c((c_func)print_basic),
		make_function_from_c((c_func)inspect_basic));
	VTAB(SYMVALPTR(sym_basic))[VIRT_NEW] = make_function_from_c((c_func)new_basic);
	VTAB(SYMVALPTR(sym_basic))[VIRT_DELETE] = SYMVALINT(sym_delete_basic);
	VTAB(SYMVALPTR(sym_basic))[VIRT_ASIZE] = SYMVALINT(sym_asize_of_basic_func);
	VTAB(SYMVALPTR(sym_basic))[VIRT_COPY] = SYMVALINT(sym_copy_basic_func);

	set_fixed_type(ID_OFF(sym_symbol), "symbol", SYMPTR(sym_basic), TYPEINFO(9,0,PTRSZ + sizeof(symbol)),
		make_function_from_c((c_func)print_symbol),
		make_function_from_c((c_func)inspect_symbol));
	VTAB(SYMVALPTR(sym_symbol))[VIRT_NEW] = def_new;
	VTAB(SYMVALPTR(sym_symbol))[VIRT_DELETE] = def_del;

	set_fixed_type(ID_OFF(sym_type), "type", SYMPTR(sym_basic), TYPEINFO(9,0,PTRSZ + sizeof(type) + 9*PTRSZ),
		make_function_from_c((c_func)print_type),
		make_function_from_c((c_func)inspect_type));
	VTAB(SYMVALPTR(sym_type))[VIRT_NEW] = make_function_from_c((c_func)new_type);
	VTAB(SYMVALPTR(sym_type))[VIRT_DELETE] = def_del;

	set_fixed_type(ID_OFF(sym_string), "string", SYMPTR(sym_basic), TYPEINFO(9,0,PTRSZ),
		make_function_from_c((c_func)print_string),
		make_function_from_c((c_func)inspect_string));

	set_fixed_type(ID_OFF(sym_function), "function", SYMPTR(sym_basic), TYPEINFO(9,0,PTRSZ),
		make_function_from_c((c_func)print_symbol), 0);
	VTAB(SYMVALPTR(sym_function))[VIRT_NEW] = def_new;
	VTAB(SYMVALPTR(sym_function))[VIRT_DELETE] = def_del;

	// TODO: a few more

	set_fixed_type(ID_OFF(sym_pair), "pair", SYMPTR(sym_object), TYPEINFO(9,0,2*PTRSZ),
		make_function_from_c((c_func)print_pair),
		make_function_from_c((c_func)inspect_pair));
	VTAB(SYMVALPTR(sym_basic))[VIRT_NEW] = make_function_from_c((c_func)new_pair);
	VTAB(SYMVALPTR(sym_basic))[VIRT_DELETE] = make_function_from_c((c_func)delete_pair);

}

int
main()
{
	void *mem;
	int size;

	init_crc();

	size = 32 * 1024*1024;
	mem = malloc(size);
	kinitheap(kglobalheap, mem, size);

	size = 2*1024*1024;
	mem = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	kinitheap(kcodeheap, mem, size);

/*
	kheapstatus(kglobalheap);

	mem = kmalloc(kglobalheap, 1234, 0, "test");
	printf("%p\n", mem);
	kheapstatus(kglobalheap);

	mem = kmalloc(kglobalheap, 1234, 0, "test");
	printf("%p\n", mem);
	kheapstatus(kglobalheap);
*/

	InitHeapAndSymbol();

//	inspect_symbol(SYMPTR(sym_global));
//	print_symbol(SYMPTR(sym_global));
//	inspect_object(EMPTY);

	return 0;
}
