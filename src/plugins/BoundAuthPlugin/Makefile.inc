all: $(BUILDDIR)BoundAuthPlugin$(DLSUFFICS)

BoundAuth$(OBJSUFFICS): BoundAuth.c
	$(CC) $(DCFLAGS) $(CFLAGS) -std=c99 $<

$(BUILDDIR)BoundAuthPlugin$(DLSUFFICS): BoundAuth$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)BoundAuth$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) $<
