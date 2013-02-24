static struct list frame_list;

void frame_init ()
{
  list_init (&frame_list);
}

void *
frame_get_frame_at (void *user_vaddr)
{
  /* Need to store data on this. */
  return palloc_get_page (PAL_USER);
}
