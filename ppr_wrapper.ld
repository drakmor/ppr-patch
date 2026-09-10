ENTRY(ppr_wrapper)

SECTIONS
{
    . = PPR_RUNTIME_CAVE_VA;
    .runtime : { *(.runtime) }
    . = PPR_PLAINTEXT_CAVE_VA;
    .plaintext : { *(.plaintext) }
    /DISCARD/ : { *(.comment) *(.note*) }
}

ASSERT(SIZEOF(.runtime) == 0x4c, "unexpected PPR runtime wrapper size")
ASSERT(SIZEOF(.plaintext) == 0xa0, "unexpected PPR plaintext wrapper size")
