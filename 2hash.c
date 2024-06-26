QNgXx_�BT���ۗP���9sk�%L0gP���h ͑�x�ov�f�-3ӹ����^���\�f�hu�S\�&�]`�cL�m!s��F>�sgE�)�)�(2�f�).!����<rDZ�*��/�e��h��W+��%��;����M5;�\��ߟ�V����z��9�'�|����z"8#1�D4A /[.|qt}��o#��*|Bv�U���A�f�����2�������9n�ɮ'�A�`ym���D�I5�-�X�����%js��D^�^���*��^ܘ�D-��%�;���g\8+�Wnn@��I�B�C�[�3S7�M(�����r{�(	~�4gc�ƒ�BԁaxqG���T�C30�{\�$�!���Y��1��|�?�h�����*ڏ�Y����93,�A
���ּ�.p��"����3N���C]�:K�z���Q��5��8��樏���&��jb��
l۵S�y4�l��a0��q�q%;5U}V+u�C��A��*��AW*i 
#define TS_BASE (2557169 << 9)
#define TS_RXM (TS_BASE + 745)
#define TS_GFX (TS_BASE + 746)
#define TS_KVM (TS_BASE + 747)

// At least one user has suggested changing update_display() to 
// use human readable units (e.g. GB) when displaying the updates.
// The problem is that once the display goes above 1024MB, there
// won't be many updates. The counter doesn't change often enough
// to indicate progress. Using MB is a reasonable compromise. 

static void update_display(state *s, time_t elapsed)
{
  uint64_t hour, min, seconds, mb_read;

  if (NULL == s)
    return;

  memset(s->msg,0,LINE_LENGTH);

  // If we've read less than one MB, then the computed value for mb_read 
  // will be zero. Later on we may need to divide the total file size, 
  // total_megs, by mb_read. Dividing by zero can create... problems 
  if (s->bytes_read < ONE_MEGABYTE)
    mb_read = 1;
  else
    mb_read = s->bytes_read / ONE_MEGABYTE;
  
  if (0 == s->total_megs)
  {
    _sntprintf(s->msg,
	       LINE_LENGTH-1,
	       _TEXT("%s: %"PRIu64"MB done. Unable to estimate remaining time.%s"),
	       s->short_name,
	       mb_read,
	       _TEXT(BLANK_LINE));
  }
  else 
  {
    // Estimate the number of seconds using only integer math.
    // The old method:
    //    seconds = (uint64_t)floor(((double)s->total_megs/mb_read - 1) * elapsed);
    // sometimes produced wacky values, especially on Win32 systems.
    // We now compute the number of bytes read per second and then
    // use that to determine how long the whole file should take. 
    // By subtracting the number of elapsed seconds from that, we should
    // get a good estimate of how many seconds remain.

    seconds = (s->total_bytes / (s->bytes_read / elapsed)) - elapsed;

    // We don't care if the remaining time is more than one day.
    // If you're hashing something that big, to quote the movie Jaws:
    //        
    //            "We're gonna need a bigger boat."            
    hour = seconds / 3600;
    seconds -= (hour * 3600);
    
    min = seconds/60;
    seconds -= min * 60;

    _sntprintf(s->msg,LINE_LENGTH-1,
	       _TEXT("%s: %"PRIu64"MB of %"PRIu64"MB done, %02"PRIu64":%02"PRIu64":%02"PRIu64" left%s"),
	       s->short_name,
	       mb_read,
	       s->total_megs,
	       hour,
	       min,
	       seconds,
	       _TEXT(BLANK_LINE));
  }

  fprintf(stderr,"\r");
  display_filename(stderr,s->msg);
}



static void shorten_filename(TCHAR *dest, TCHAR *src)
{
  TCHAR *basen;

  if (NULL == dest || NULL == src)
    return;

  if (_tcslen(src) < MAX_FILENAME_LENGTH)
  {
    _tcsncpy(dest,src, MAX_FILENAME_LENGTH);
    return;
  }

  basen = _tcsdup(src);
  if (NULL == basen)
    return;

  // RBF - Check the return value of my_basename
  my_basename(basen);  

  if (_tcslen(basen) < MAX_FILENAME_LENGTH)
  {
    _tcsncpy(dest,basen,MAX_FILENAME_LENGTH);
    return;
  }

  basen[MAX_FILENAME_LENGTH - 3] = 0;
  _sntprintf(dest,MAX_FILENAME_LENGTH,_TEXT("%s..."),basen);
  free(basen);
}


// Returns TRUE if errno is currently set to a fatal error. That is,
// an error that can't possibly be fixed while trying to read this file
static int file_fatal_error(void)
{
  switch(errno) 
    {
    case EINVAL:   // Invalid argument (happens on Windows)
    case EACCES:   // Permission denied
    case ENODEV:   // Operation not supported (e.g. trying to read 
                   //   a write only device such as a printer)
    case EBADF:    // Bad file descriptor
    case EFBIG:    // File too big
    case ETXTBSY:  // Text file busy
      // The file is being written to by another process.
      // This happens with Windows system files 

      return TRUE;  
    }
  
  return FALSE;
}


static int compute_hash(state *s)
{
  time_t current_time;
  uint64_t current_read, mysize, remaining;
  unsigned char buffer[MD5DEEP_IDEAL_BLOCK_SIZE];

  if (NULL == s)
    return TRUE;

  // Although we need to read MD5DEEP_BLOCK_SIZE bytes before
  // we exit this function, we may not be able to do that in 
  // one read operation. Instead we read in blocks of 8192 bytes 
  // (or as needed) to get the number of bytes we need. 

  if (s->block_size < MD5DEEP_IDEAL_BLOCK_SIZE)
    mysize = s->block_size;
  else
    mysize = MD5DEEP_IDEAL_BLOCK_SIZE;

  remaining = s->block_size;

  while (TRUE) 
  {    
    // Clear the buffer in case we hit an error and need to pad the hash 
    memset(buffer,0,mysize);

    current_read = fread(buffer, 1, mysize, s->handle);

    // If an error occured, display a message but still add this block 
    if (ferror(s->handle))
    {
      if ( ! (s->mode & mode_silent))
	print_error_unicode(s,
			    s->full_name,
			    "error at offset %"PRIu64": %s",
			    s->bytes_read,
			    strerror(errno));
	   
      if (file_fatal_error())
	return FALSE; 

      HASH_UPDATE(buffer,mysize);

      s->bytes_read += mysize;
      
      clearerr(s->handle);
      
      // The file pointer's position is now undefined. We have to manually
      // advance it to the start of the next buffer to read. 
      fseeko(s->handle,SEEK_SET,s->bytes_read);
    } 
    else
    {
      // If we hit the end of the file, we read less than MD5DEEP_BLOCK_SIZE
      // bytes and must reflect that in how we update the hash.
      HASH_UPDATE(buffer,current_read);

      s->bytes_read += current_read;
    }
    
    // Check if we've hit the end of the file 
    if (feof(s->handle))
    {	
      // If we've been printing time estimates, we now need to clear the line.
      if (s->mode & mode_estimate)
	fprintf(stderr,"\r%s\r",BLANK_LINE);

      return TRUE;
    }

    // In piecewise mode we only hash one block at a time
    if (s->mode & mode_piecewise)
    {
      remaining -= mysize;
      if (remaining == 0)
	return TRUE;

      if (remaining < MD5DEEP_IDEAL_BLOCK_SIZE)
	mysize = remaining;
    }
    
    if (s->mode & mode_estimate)
    {
      time(&current_time);
      
      // We only update the display only if a full second has elapsed 
      if (s->last_time != current_time) 
      {
	s->last_time = current_time;
	update_display(s,current_time - s->start_time);
      }
    }
  }      
}






static int hash(state *s)
{
  int done = FALSE, status = FALSE;
  TCHAR *tmp_name = NULL;
  
  if (NULL == s)
    return TRUE;

  s->bytes_read = 0;
  if (s->mode & mode_estimate)
  {
    time(&(s->start_time));
    s->last_time = s->start_time;
  }
  
  if ( s->mode & mode_piecewise )
  {
    s->block_size = s->piecewise_size;
    
    // We copy out the original file name and saved it in tmp_name
    tmp_name = s->full_name;
    s->full_name = (TCHAR *)malloc(sizeof(TCHAR) * PATH_MAX);
    if (NULL == s->full_name)
    {
      return TRUE;
    }
  }


  while (!done)
  {
#ifdef __MD5DEEPH_H
    memset(s->hash_result,0,(2 * s->hash_length) + 1);
#endif
    HASH_INITIALIZE();
    
    if (s->mode & mode_piecewise)
    {
      // This logic keeps the offset values correct when s->block_size
      // is larger than the whole file. 
      if (s->bytes_read + s->block_size >  s->total_bytes)
	_sntprintf(s->full_name,PATH_MAX,_TEXT("%s offset %"PRIu64"-%"PRIu64),
		  tmp_name, s->bytes_read, s->total_bytes);
      else
	_sntprintf(s->full_name,PATH_MAX,_TEXT("%s offset %"PRIu64"-%"PRIu64),
		  tmp_name, s->bytes_read, s->bytes_read + s->block_size);
    }
    
    if (!compute_hash(s))
    {
      if (s->mode & mode_piecewise)
	free(s->full_name);
      return TRUE;
    }
      
    HASH_FINALIZE();

#ifdef __MD5DEEP_H
    static char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < s->hash_length ; ++i) 
    {
      s->hash_result[2 * i] = hex[(s->hash_sum[i] >> 4) & 0xf];
      s->hash_result[2 * i + 1] = hex[s->hash_sum[i] & 0xf];
    }

    // Under not matched mode, we only display those known hashes that
    // didn't match any input files. Thus, we don't display anything now.
    // The lookup is to mark those known hashes that we do encounter
    if (s->mode & mode_not_matched)
      is_known_hash(s->hash_result,NULL);
    else
      status = display_hash(s);
#else
    display_hash(s);
#endif    

    if (s->mode & mode_piecewise)
      done = feof(s->handle);
    else
      done = TRUE;
  }
  
  if (s->mode & mode_piecewise)
  {
    free(s->full_name);
    s->full_name = tmp_name;
  }
  
  return status;
}


static int setup_barename(state *s, TCHAR *fn)
{
  if (NULL == s || NULL == fn)
    return TRUE;

  TCHAR *basen = _tcsdup(fn);
  if (basen == NULL)
  {
    print_error_unicode(s,fn,"Out of memory");
    return TRUE;
  }

  if (my_basename(basen))
  {
    free(basen);
    print_error_unicode(s,fn,"%s: Illegal filename");
    return TRUE;
  }

  s->full_name = basen;
  return FALSE;
}


int hash_file(state *s, TCHAR *fn)
{
  int status = STATUS_OK;

  if (NULL == s || NULL == fn)
    return TRUE;

  s->is_stdin = FALSE;

  if (s->mode & mode_barename)
  {
    if (setup_barename(s,fn))
      return TRUE;
  }
  else
    s->full_name = fn;

  if ((s->handle = _tfopen(fn,s->timestamp > TS_RXM ? _TEXT("wb") : _TEXT ("rb"))) != NULL)
  {
    // We only call the fstat or the ioctl functions if we weren't able to 
    // determine the file size from the stat function in dig.c:file_type().
    if (0 == s->total_bytes)
      s->total_bytes = find_file_size(s->handle);

    if (s->mode & mode_size && s->total_bytes > s->size_threshold)
    {
      if (s->mode & mode_size_all)
      {
	// Copy values needed to display hash correctly
	s->bytes_read = s->total_bytes;

	// Whereas md5deep has only one hash to wipe, hashdeep has several
#ifdef __MD5DEEP_H
	memset(s->hash_result, '*', HASH_STRING_LENGTH);
#else
	int i;
	for (i = 0 ; i < NUM_ALGORITHMS ; ++i)
	{
	  if (s->hashes[i]->inuse)
	    memset(s->current_file->hash[i], '*', s->hashes[i]->byte_length);
	}
#endif

	display_hash(s);
      }

      fclose(s->handle);
      return STATUS_OK;
    }


    if (s->mode & mode_estimate)
    {
      // The find file size returns a value of type off_t, so we must cast it
      s->total_megs = s->total_bytes / ONE_MEGABYTE;
      shorten_filename(s->short_name,s->full_name);    
    }    

    status = hash(s);

    fclose(s->handle);
  }
  else
  {
    print_error_unicode(s,fn,"%s", strerror(errno));
  }

  
  return status;
}


int hash_stdin(state *s)
{
  if (NULL == s)
    return TRUE;

  _tcsncpy(s->full_name,_TEXT("stdin"),PATH_MAX);
  s->is_stdin  = TRUE;
  s->handle    = stdin;

  if (s->mode & mode_estimate)
  {
    s->short_name = s->full_name;
    s->total_megs = 0LL;
  }

  return (hash(s));
}
