#include <roken.h>

/**
 * Reads a line from the input stream. The end line character is _not_
 * stored in the return buffer, but the return buffer is null terminated.
 * The caller is responsible for freeing the memory allocated in buffer.
 * The size of the buffer is stored in size.
 * You can specify that backslash terminated lines are treated as one line 
 * (and put in the same buffer).
 *
 * @return  Number of chars read- 0 or more, -1 on an error with errno set or
 *          when the eof is reached. On an error or eof, size will be 0 and
 *          there will be no memory to free.
 */
int qas_krb5_readline(FILE* input, char** buffer, size_t* size_ptr);

/**
 * Scans the input stream for a line that has the given key in the given
 * column. The columns are determined by the delimiter char. The line_ptr
 * pointer should point to a buffer that will hold the line results. If
 * line_ptr is NULL, then the looked up line will not be copied and the
 * function turns into a simple lookup function. If line_ptr is not
 * NULL and can_resize_line is set to 1, then the line_ptr buffer may
 * be resized during the parsing of the file. If can_resize_line is set to
 * 0, then ENOMEM will be returned if the buffer is not big enough to hold
 * the results.
 *
 * @param input     The input stream
 * @param key       The string which is the key
 * @param delimiter The character which separates the columns
 * @param column    The column index (0 based)
 * @param line_ptr  The address of a char* to store the line in, if the
 *                  the char* is NULL memory will be allocated to hold the
 *                  line entry. If you are not interested in the line's
 *                  contents that the entry is in, then pass NULL.
 * @param linesize_ptr   The address of size_t value that holds the size of
 *                       the char*
 * @param can_resize_line  Flag to denote if the buffer pointed to by
 *                         line_ptr can be resized. This is useful for the
 *                         NSS module since it's given a buffer that cannot
 *                         be resized. If line_ptr is not NULL and
 *                         can_resize_line is 0, then the line contents will
 *                         be copied into *line_ptr if it is big enough.
 *
 * @return     0 if a line with the key is found,
 *             ENOENT if a line with the key was not found, and
 *             ENOMEM if the buffer pointed to by line_ptr is not big enough
 *             to hold the line, and can_resize_line was 0
 */

int qas_krb5_find_entry( FILE* input,
                         const char* key,
                         char delimiter,
                         int column,
                         char** line_ptr,
                         size_t* linesize_ptr,
                         int can_resize_line );

