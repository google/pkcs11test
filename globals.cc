#include "globals.h"

CK_FUNCTION_LIST_PTR g_fns = nullptr;
CK_SLOT_ID g_slot_id = 0;
bool g_login_required = false;
const char* g_user_pin = "useruser";
const char* g_so_pin = "sososo";
bool g_rng = false;
