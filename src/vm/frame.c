/* Need to be able to get an address of a frame that we can write to.
   Should evict a frame if it needs to.
   Need to know what "evicting" means.
   If the page was read only then eviction just means doing nothing.
   Otherwise we need to write it back to its file or to swap.
*/

/* In order to work we need to store our kernel address.
   We also need to store our user address for our evcition. */

struct frame_table_entry
{
  void *frame_addr;
  void *user_addr;
  uint32_t *pd;
}

static struct list free_list;
static struct list used_list;

void frame_init ()
{
  list_init (&used_list);
  list_init (&free_list);
}

void *
frame_get_frame_at (void *user_vaddr, uint32_t *pd)
{
  /* Need to check free list. */
  
  void *frame = palloc_get_page (PAL_USER);

  if (frame)
    {
      struct frame_table_entry *record = malloc (sizeof (frame_table_entry));
      record->frame_addr = frame;
      record->user_addr = user_vaddr;
      record->pd = pd;
      return frame;
    }
  else
    {
      return NULL;
    }
}
