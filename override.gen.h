/*[[[cog
import cog

with open("override.syms", "r") as fl:
    syms = [sym.strip() for sym in fl.readlines()]

for sym in syms:
    cog.outl("static typeof(&%s) o_%s;" % (sym, sym))
cog.outl("")

for sym in syms:
    cog.outl("#define %s (*o_%s)" % (sym, sym))
cog.outl("")
]]]*/
//[[[end]]]

static const struct o_sym {
	char *orig_name;
	unsigned long *sym;
} o_syms[] = {
/*[[[cog
for sym in syms:
    cog.out("\t")
    cog.outl('{"%s", (unsigned long *)&o_%s},' % (sym, sym))
]]]*/
//[[[end]]]
};
