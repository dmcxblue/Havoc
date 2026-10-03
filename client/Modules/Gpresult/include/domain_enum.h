#ifndef DOMAIN_ENUM_H
#define DOMAIN_ENUM_H

/*
 * `gpresult domain` — sweep every GPO-related ACL the caller's token touches.
 * See PLAN-DOMAIN.md for the full design.
 */
void GpresultDomainSweep(int verbose);

#endif /* DOMAIN_ENUM_H */
