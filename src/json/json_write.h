/*
 * JSON serializer. Every string value is escaped -- no exceptions
 * (plan 7.5); there is no "raw" append path that bypasses it.
 */
#ifndef PS_JSON_JSON_WRITE_H
#define PS_JSON_JSON_WRITE_H

#include <stdbool.h>

#include "json/json_parse.h"
#include "platform/buf.h"

/*
 * Appends the JSON serialization of v to buf. Returns false only on
 * allocation failure inside buf, in which case buf may hold a partial
 * write and should be discarded rather than reused.
 */
bool ps_json_write(const ps_json_value_t *v, ps_buf_t *buf);

#endif /* PS_JSON_JSON_WRITE_H */
