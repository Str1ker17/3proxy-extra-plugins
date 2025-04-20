all: $(BUILDDIR)BoundAuthPlugin$(DLSUFFICS)

BoundAuth$(OBJSUFFICS): BoundAuth.c
	$(CC) $(DCFLAGS) $(CFLAGS) $<

$(BUILDDIR)BoundAuthPlugin$(DLSUFFICS): BoundAuth$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)BoundAuth$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) $<
