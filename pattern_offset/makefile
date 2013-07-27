PROC=pattern_offset
include ../plugin.mak

clean:
	@rm -rf ./obj
# MAKEDEP dependency list ------------------
$(F)pattern_offset$(O)   : $(I)area.hpp $(I)bytes.hpp $(I)fpro.h $(I)funcs.hpp       \
	          $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp     \
	          $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp                 \
	          $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp      \
	          $(I)xref.hpp pattern_offset.cpp
