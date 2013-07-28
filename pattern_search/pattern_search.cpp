/**
 * Search for cyclic patterns in memory and registers.
 * qnix <qnix@0x80.org>
 */
#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <string>
#include <sstream>
#include <map>
#include <vector>

#define PATTERN_MAX 20280
#define PATTERN_NOT_FOUND -1

typedef std::map<ea_t, ea_t> range_t;
typedef std::map<ea_t, int> result_t;

static std::vector<std::string> split(const std::string& s, const char &seperator);
static std::string idaapi pattern_create(const uval_t &size);
static int idaapi pattern_offset(const ea_t &content);
static pid_t idaapi askpid(void);
static void idaapi run(int);
static int idaapi init(void);
static char * idaapi get_maps(const int &pid);
static void idaapi find_writeable_ranges(char *maps, range_t &ranges);
static void idaapi show_results(result_t result);
static void idaapi search_writeable_memory(result_t &found, range_t ranges);
void idaapi term(void);
static int idaapi thread_search(void *ud);

qthread_t children[2];
int nchilds;
static range_t wranges;
static std::string pattern = pattern_create(PATTERN_MAX);

/**
 * PLUGIN DESCRIPTION BLOCK
 */
static const char comment[]       = "Search for cyclic patterns in memory and registers";
static const char wanted_name[]   = "pattern_search";
static const char wanted_hotkey[] = "";
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,           // plugin flags
  init,                 // initialize
  term,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  comment,              // ea_t comment about the plugin
  NULL,                 // multiline help about the plugin
  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};

/**
 * split a string with separator
 * @param s the string to split
 * @param separator
 * @return splitted parts
 */
static std::vector<std::string> split(const std::string& s, const char &seperator)
{
    std::vector<std::string> output;
    std::string::size_type prev_pos = 0, pos = 0;
    while((pos = s.find(seperator, pos)) != std::string::npos)
    {
        std::string substring( s.substr(prev_pos, pos-prev_pos) );
        output.push_back(substring);
        prev_pos = ++pos;
    }
    output.push_back(s.substr(prev_pos, pos-prev_pos));
    return output;
}


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
 * @param content to find
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
 * Ask for pid.
 */
static pid_t idaapi askpid(void)
{
   static const char form[] =
        "Enter id for debugged process\n"
        "\n"
        "  <~P~id:D1:100:10::>\n"
        "\n"
        "\n";
    pid_t pid = 0;
    if( AskUsingForm_c(form, &pid) > 0)
        return pid;
    return -1;
}

/**
 * @param pid the process id
 * @return content of /proc/pid/maps
 */
static char * idaapi get_maps(const int &pid)
{
    FILE *maps_fd = NULL;
    char *maps    = (char*)qalloc(QMAXPATH);

    if(!maps)
        return NULL;

    qsnprintf(maps, QMAXPATH-1, "/proc/%d/maps", pid);

    maps_fd = qfopen(maps, "r");
    if(maps_fd == NULL)
        return NULL;
    
    qfread(maps_fd, maps, QMAXPATH-1);
    qfclose(maps_fd);

    return maps;
}

/**
 * Get the writeable ranges
 * @param maps the content of /proc/pid/maps
 * @param ranges the writeable ranges
 */
static void idaapi find_writeable_ranges(char *maps, range_t &ranges)
{
    std::vector<std::string> splits;
    std::stringstream ss(maps);
    std::string line;
    int current = 0;

    while(std::getline(ss, line, ' '))
    {
        splits.push_back(line);
        if(line.length() == 4)
        {
            if(line.find("w") != std::string::npos)
            {
                std::string fromto = split(splits.at(current-1), '\n')[1];
                std::string from   = split(fromto, '-')[0];
                std::string to     = split(fromto, '-')[1];
                ranges.insert( std::pair<ea_t, ea_t>(
                            strtoul(from.c_str(), NULL,16),
                            strtoul(to.c_str(), NULL, 16)
                            ));
            }
        }
        current++;
    }

}

/**
 * Show results
 * @param result contains address->offset
 */
static void idaapi show_results(result_t result)
{
    for(result_t::iterator it=result.begin();
            it!=result.end();
            it++)
    {
        ea_t address = it->first;
        int offset   = it->second;
        msg("Found at %p offset %d\n", address, offset);
    }
}

/**
 * Search writeable memories for patterns
 * @param found found address that contain pattern
 * @param ranges the ranges to serch in <from, to>
 */
static void idaapi search_writeable_memory(result_t &found, range_t ranges)
{
    for(range_t::iterator it= ranges.begin();
            it!=ranges.end();
            it++)
    {
        msg("%p to %p\n", it->first, it->second);
        ea_t start = it->first;
        ea_t end   = it->second;

        while(start < end-4)
        {
            int content = get_byte(start);
            content = (content << 8) + get_byte(start+1);
            content = (content << 8) + get_byte(start+2);
            content = (content << 8) + get_byte(start+3);
            
            if(content)
            {
                int offset = pattern_offset(content);
                if(offset != PATTERN_NOT_FOUND)
                {
                    found.insert(std::pair<ea_t, int>(
                                start,
                                offset
                                ));
                }
            }
            start++;
        }
    }
}

/**
 * Run pattern search thread
 */
static int idaapi thread_search(void *ud)
{
    result_t found;
    msg("Searching in writeable memory :\n");
    search_writeable_memory(found, wranges);

    // preview found patterns
    msg("Results :\n");
    show_results(found);
    term();
#ifdef __GNUC__
    return 0;
#endif
}

/**
 * Terminate
 */
void idaapi term(void)
{
    // kill threads
    if(nchilds > 0)
    {
        for(int i=0;i<nchilds;i++)
        {
            qthread_kill(children[i]);
            qthread_join(children[i]);
            qthread_free(children[i]);
        }
        nchilds = 0;
    }
}

/**
 * Run
 */
static void idaapi run(int)
{

    if(!dbg)
    {
        msg("Can't search no debugger is loaded\n");
        return;
    }

    pid_t pid = askpid();

    register_info_t *greg = NULL;
    regval_t gval;
    regval_t espval;

    for(int i=0;i< dbg->registers_size;i++)
    {
        greg = (dbg->registers+i);
        // Get value in register
        get_reg_val(greg->name, &gval);
        if(!stricmp(greg->name, "ESP"))
        {
            espval = gval;
        }
        // Search if register contain cyclic pattern
        int offset = pattern_offset(gval.ival);
        if(offset != PATTERN_NOT_FOUND) 
        {
            msg("Found pattern in %s offset %d\n", greg->name, offset);
        }
    }

    // get /proc/pid/maps content
    char *maps = get_maps(pid);
    if(!maps)
    {
        msg("Unable to get maps\n");
        return;
    }

    // find writeable memory ranges for /proc/PID/maps
    find_writeable_ranges(maps, wranges);
    qfree(maps);

    if(nchilds != 0) // threads kill?
        term();

    // searching thread in writeable ranges for patterns
    if(nchilds == 0)
    {
        children[nchilds] = qthread_create(thread_search, (void *)nchilds);
        nchilds++;
    }
}

static int idaapi init(void)
{
    return PLUGIN_KEEP;
}
