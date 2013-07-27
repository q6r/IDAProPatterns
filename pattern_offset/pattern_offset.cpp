/**
 * Find offset of cyclic pattern
 * qnix <qnix@0x80.org>
 */
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <string>

#define PATTERN_MAX 20280
#define PATTERN_NOT_FOUND -1

static int idaapi pattern_offset(const ea_t &content);
static std::string idaapi pattern_create(const uval_t &size);
static void idaapi run(int);
static int idaapi init(void);

static std::string pattern = pattern_create(PATTERN_MAX);

/*
 * PLUGIN DESCRIPTION BLOCK
 */
static const char comment[]       = "Find offset for cyclic pattern";
static const char wanted_name[]   = "pattern_offset";
static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL,           // plugin flags
  init,                 // initialize
  NULL,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // long comment about the plugin
  NULL,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

/**
 * Generate cyclic patterns
 * @param size the size of pattern
 * @return cyclic pattern 
 */
static std::string idaapi pattern_create(const uval_t &size)
{
    std::string pattern;
    std::string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string b = "abcdefghijklmnopqrstuvwxyz";
    std::string c = "0123456789";

    int ai, bi, ci;
    ai = bi = ci = 0;

    while(pattern.length() < size) {
        pattern += a[ai];
        pattern += b[bi];
        pattern += c[ci];
        ci++;

        if(ci == c.length()) {
            ci = 0;
            bi++;
        }
        if(bi == b.length()) {
            bi = 0;
            ai++;
        }
        if(ai == a.length())
            ai=0;
    }
    return pattern;
}

/**
 * Find pattern offset
 * @param address the address to find
 * @return offset or PATTERN_NOT_FOUND
 */
static int idaapi pattern_offset(const ea_t &content)
{
    char a1 = content >> 24 & 0xff;
    char a2 = content >> 16 & 0xff;
    char a3 = content >> 8  & 0xff;
    char a4 = content >> 0  & 0xff;

    for(int i=0;i<=PATTERN_MAX-4;i++)
    {
        bool found = pattern.at(i) == a1
            && pattern.at(i+1) == a2
            && pattern.at(i+2) == a3
            && pattern.at(i+3) == a4;
        if(found)
            return i;
        found = pattern.at(i)  == a4
            && pattern.at(i+1) == a3
            && pattern.at(i+2) == a2
            && pattern.at(i+3) == a1;
        if(found)
            return i;
    }
    return PATTERN_NOT_FOUND;
}


/**
 * Run
 */
static void idaapi run(int)
{
    static const char form[] =
        "Enter length of pattern\n"
        "\n"
        "  <~A~ddress:D1:100:10::>\n"
        "\n"
        "\n";
    int address = 0, offset = 0;
    if( AskUsingForm_c(form, &address) > 0)
        offset = pattern_offset(address);
    if(offset == PATTERN_NOT_FOUND)
        msg("Unable to find offset\n");
    else
        msg("Offset at %d\n", offset);

}

static int idaapi init(void)
{
    return PLUGIN_OK;
}


