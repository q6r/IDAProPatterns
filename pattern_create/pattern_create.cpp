/**
 * Create cyclic patterns
 * qnix <qnix@0x80.org>
 */
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <string>

static void idaapi pattern_create(const uval_t &size);
static void idaapi run(int);
static int idaapi init(void);

/*
 * PLUGIN DESCRIPTION BLOCK
 */
static const char comment[]       = "Create cyclic pattern";
static const char wanted_name[]   = "pattern_create";
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
static void idaapi pattern_create(const uval_t &size)
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
    msg("pattern : %s\n", pattern.c_str());
}

/**
 * Run
 */
static void idaapi run(int)
{
    static const char form[] =
        "Enter length of pattern\n"
        "\n"
        "  <~L~ength:D1:100:10::>\n"
        "\n"
        "\n";
    uval_t size = 0;
    if( AskUsingForm_c(form, &size) > 0)
        pattern_create(size);
}

static int idaapi init(void)
{
    return PLUGIN_OK;
}
