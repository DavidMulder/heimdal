#include <krb5_util.h>
#include <ctype.h>

#define TMPBUF_SIZE 1024
#define EOL_CHAR    '\n'

static char* krb5_string_strstripL(const char* start)
{
    while( start && *start && isspace((int)*start) )
        start++;

    return (char*) start;
}

int krb5_readline( FILE* input, 
                   char** buffer, 
                   size_t* size_ptr )
{
    int   rval = -1;
    int   buf_size = 0;

    /* Setting this to 1 will prevent users from logging in on AIX because we
     * will remove the initial whitespace in methods.cfg.
     */
    int trim_white_left = 0;

    size_t available_size;
    size_t amount_read = 0;
    size_t filled_size = 0;

    char* runner = NULL;

    /* fail gracefully on non-existent input stream */
    if( input == NULL )
    {
        errno = EINVAL;
        goto CLEANUP;
    }

    if( *buffer == NULL )
    {
        /* create the buffer */
        if( (*buffer = malloc( TMPBUF_SIZE )) == NULL )
            goto NOMEM_ERR;

        buf_size = TMPBUF_SIZE;
    }
    else
    {
        if( size_ptr )
            buf_size = *size_ptr;
        else
        {
            errno = EINVAL;
            goto CLEANUP;
        }
    }

    /* Zero out provided (or malloced) buffer */
    memset( *buffer, 0, buf_size );

    runner = *buffer;
    available_size = buf_size - 1;

    /* read out of the file stream, quit on EOF */
    while( 1 )
    {
        errno = 0;
        if( fgets( runner, available_size, input ) != NULL )
        {
            rval = 0;
            amount_read = strlen(runner);

            if( trim_white_left )
            {
                if( *runner != '\n' )
                {
                    char* trimmed_buff;
                    if( (trimmed_buff = krb5_string_strstripL( runner )) == NULL )
                    {
                        errno = EINVAL;
                        goto CLEANUP;
                    }

                    size_t trimmed_len = strlen(trimmed_buff); /* if trimmed_len is 0, then the runner contained all whitespace */

                    if( amount_read > trimmed_len )/* we trimmed whitespace */
                    {
                        if( trimmed_len )
                        {
                            trim_white_left = 0;
                        }
                        if( runner != trimmed_buff )
                        {
                            memmove(runner, trimmed_buff, trimmed_len + 1);
                        }
                    }
                }
            }

            filled_size = strlen(*buffer);

            if( (*buffer)[filled_size - 1] == EOL_CHAR || (*buffer)[filled_size
                    - 1] == '\0' || available_size - 1 != amount_read )
            {
                /* end of line */
                break;
            }
            else
            {
                /* hit the end of the buffer, make it bigger */
                int   new_buf_size = buf_size * 2;
                char* new_buf = NULL;
                if( (new_buf = realloc( *buffer, new_buf_size )) == NULL )
                    goto NOMEM_ERR;
                else
                    *buffer = new_buf;
    
                /* since fgets zeros out the last char, we point runner to
                 * the last char in the previous buffer */
                runner = (*buffer) + (filled_size);
                buf_size = new_buf_size;

                /* since we're actually in the previous buffer still, i.e.
                 * runner points to char _before_ malloc'd memory */
                available_size = buf_size - filled_size;

                /* zero out the unused portion of the realloced buffer */
                memset(runner, 0, available_size);
            }
        }
        else if( errno != EINTR )
        {
            /* if we got EINTR we were interrupted and we should keep on  *
             * trying to read because there should still be bytes to read */
            break;
        }
    } /* End while(1) */

    /* return how much we read, or -1 if EOF or error */
    if( rval > -1 )
    {
        /* figure out the length, discard end of line chars */
        rval = (runner - (*buffer)) + strlen( runner );
        if( rval > 0 )
        {
            /* get rid of the eol if it's there */
            if( (*buffer)[rval-1] == EOL_CHAR )
            {
                (*buffer)[rval-1] = '\0';
                rval--;
            }

            /* check for windows end of line chars too */
            if( rval > 0 && (*buffer)[rval-1] == '\r' )
            {
                (*buffer)[rval-1] = '\0';
                rval--;
            }
        }
    }

    goto CLEANUP;

NOMEM_ERR:
    rval = -1;
    errno = ENOMEM;

CLEANUP:
    if( rval == -1 && *buffer )
    {
        free( *buffer );
        *buffer = NULL;
        buf_size = 0;
    }

    if( size_ptr )  *size_ptr = buf_size;

    return rval;
}

int krb5_find_entry( FILE* input,
                     const char* key,
                     char delimiter,
                     int column,
                     char** line_ptr,
                     size_t* linesize_ptr,
                     int can_resize_line )
{
    int     result = ENOENT;
    int     bytesread = 0;
    int     keylen = 0;
    char*   slider;
    char*   end;
    int     i = 0;
    char*   myline = NULL;
    size_t  mylinesize = 0;
    char**  myline_ptr = NULL;
    size_t* mylinesize_ptr = 0;

    if( input == NULL || key == NULL || *key == '\0' )
        goto CLEANUP;

    if( line_ptr && can_resize_line )
    {
        myline_ptr = line_ptr;
        mylinesize_ptr = linesize_ptr;
    }
    else
    {
        myline_ptr = &myline;
        mylinesize_ptr = &mylinesize;
    }

    keylen = strlen( key );
    while( (bytesread = krb5_readline( input,
                                       myline_ptr,
                                       mylinesize_ptr )) >= 0 )
    {
        slider = *myline_ptr;
        for( i = 0; i < column; i++ )
        {
            slider = strchr( slider, delimiter );
            if( slider == NULL )
                break;

            slider ++;
        }

        if(slider == NULL)
        {
            slider = *myline_ptr;
        }
        if( column == 0 && *slider == '+' )
            ++slider;
        end = strchr(slider,delimiter);
        if( end == NULL && column == 0 )
            end = slider + strlen(slider);

        if( (end - slider) == keylen &&
            (strncmp( key, slider, keylen ) == 0) )
        {
            result = 0;

            /* if can_resize_line was 0, then we need to copy the results into
             * the passed in buffer, the NSS module can't resize the buffer
             * we need to store the result in */
            if( !can_resize_line && line_ptr && linesize_ptr )
            {
                if( (int)(*linesize_ptr) < (bytesread + 1) )
                {
                    result = ENOMEM;
                    goto CLEANUP;
                }

                memcpy( *line_ptr, *myline_ptr, bytesread );
                (*line_ptr)[bytesread] = '\0';
            }

            goto CLEANUP;
        }
    }

CLEANUP:
    if( myline ) free( myline );

    return result;
}

