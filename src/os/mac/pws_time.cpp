/*
* Copyright (c) 2003-2025 Rony Shapiro <ronys@pwsafe.org>.
* All rights reserved. Use of the code is allowed under the
* Artistic License 2.0 terms, as specified in the LICENSE file
* distributed with this code, or available from
* http://www.opensource.org/licenses/artistic-license-2.0.php
*/

/**
 * \file MacOS-specific implementation of some time related functionality
 */

#include "pws_time.h"
#include "../utf8conv.h"

int localtime64_r(const __time64_t *timep, struct tm *result)
{
  return localtime_r((const time_t *)timep, result) == 0;
}

