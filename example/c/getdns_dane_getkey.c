/* getdns_dane_getkey.c
 * Glen Wiley <gwiley@verisign.com>
 *
 * leverage the getdns API to fetch a TLSA record - a public key
 *
 */

#include <getdns/getdns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ERROR_STRING 80

/*---------------------------------------- usage */
void
usage()
{
    printf(
     "USAGE: getdns_dane_getkey [-h] -d <domain_name>\n"
     "\n"
     "-d <domain_name>  fetch key from the specified record via DNS\n"
     "                example: _443._tcp.tnw.verisignlabs.com\n"
     "\n"
     );

    return;
} /* usage */

/*---------------------------------------- getkeyviadane
  fetch the smime/a key identified by the encoded keyid and host name
  populate *certtxt with the key record, caller must free certtxt
*/
void
getkeyviadane(char *dname, int rrtype, char **certtxt)
{
    int      i;
    uint32_t status;
    size_t   nans;
    size_t   numrrs;
    int      rrnum;
    char     getdnserr[MAX_ERROR_STRING+1];
    uint32_t recrrtype;
    getdns_return_t getdnsret;
    getdns_context  *getdnsctx = NULL;
    getdns_dict     *getdnsrsp = NULL;
    getdns_dict     *dnsrec    = NULL;
    getdns_dict     *rr        = NULL;
    getdns_dict     *rrdata    = NULL;
    getdns_list     *dnsreplytree = NULL;
    getdns_list     *dnsans    = NULL;
    getdns_bindata  *rawrdata  = NULL;

    *certtxt = NULL;

    // create the context for DNS resolution using local OS system settings

    getdnsret = getdns_context_create(&getdnsctx, 1);
    if(getdnsret != GETDNS_RETURN_GOOD)
    {
        getdns_strerror(getdnsret, getdnserr, MAX_ERROR_STRING);
        fprintf(stderr, "error creating getdns context, %d, %s\n"
         , getdnsret, getdnserr);
        return;
    }

    // getdns_context_set_resolution_type(getdnsctx, GETDNS_RESOLUTION_STUB);

    // perform the DNS resolution request

    getdnsret = getdns_general_sync(getdnsctx, dname, rrtype, NULL, &getdnsrsp);
    if(getdnsret != GETDNS_RETURN_GOOD)
    {
        getdns_strerror(getdnsret, getdnserr, MAX_ERROR_STRING);
        fprintf(stderr, "DNS request failed, %d, %s\n", getdnsret, getdnserr);

        getdns_dict_destroy(getdnsrsp);
        getdns_context_destroy(getdnsctx);

        return;
    }

    // sanity check the result of the query

    getdnsret = getdns_dict_get_int(getdnsrsp, (char *) "status", &status);
    if(getdnsret != GETDNS_RETURN_GOOD || status != GETDNS_RESPSTATUS_GOOD)
    {
        fprintf(stderr, "DNS request did not return results\n");

        getdns_dict_destroy(getdnsrsp);
        getdns_context_destroy(getdnsctx);

        return;
    }

    getdnsret = getdns_dict_get_list(getdnsrsp, (char *)"replies_tree", &dnsreplytree);
    if(getdnsret != GETDNS_RETURN_GOOD)
    {
        fprintf(stderr, "DNS reply tree empty\n");

        getdns_dict_destroy(getdnsrsp);
        getdns_context_destroy(getdnsctx);

        return;
    }

    nans = 0;
    getdns_list_get_length(dnsreplytree, &nans); 
    for(i=0; i<nans && *certtxt == NULL; i++)
    {
        // extract a record from the reply tree, extract answer from that record

        getdns_list_get_dict(dnsreplytree, i, &dnsrec);

        getdnsret = getdns_dict_get_list(dnsrec, (char *)"answer", &dnsans);
        if(getdnsret != GETDNS_RETURN_GOOD)
        {
            fprintf(stderr, "answer missing from DNS reply tree, exiting\n");
            exit(1);
        }

        // walk the RRs in the DNS answer

        getdns_list_get_length(dnsans, &numrrs);
        for(rrnum=0; rrnum < numrrs && *certtxt == NULL; rrnum++)
        {
            getdns_list_get_dict(dnsans, rrnum, &rr);
            recrrtype = 0;
            getdns_dict_get_int(rr, (char *)"type", &recrrtype);
            if(recrrtype == rrtype)
            {
                getdns_dict_get_dict(rr, (char *)"rdata", &rrdata);
                getdnsret = getdns_dict_get_bindata(rrdata, (char *)"rdata_raw"
                 , &rawrdata);
                if(getdnsret != GETDNS_RETURN_GOOD)
                {
                    fprintf(stderr, "error, rdata missing address\n");
                }
                else
                {
                    *certtxt = (char *) malloc(rawrdata->size + 1);
                    memcpy(*certtxt, rawrdata->data, rawrdata->size);
                    *certtxt[rawrdata->size] = '\0';
                }
            }
        } // for rrnum
    } // for i in nans

    getdns_dict_destroy(getdnsrsp);
    getdns_context_destroy(getdnsctx);

    return;
} // getkeyviadane

/*---------------------------------------- main */
int
main(int argc, char* argv[])
{
    int opt;
    char *fn_src   = NULL;
    char *dname    = NULL;
    char *certtxt  = NULL;

    while((opt=getopt(argc, argv, "h?f:d:")) != EOF)
    {
        switch(opt)
        {
            case 'f':
                fn_src = optarg;
                break;

            case 'd':
                dname = optarg;
                break;

            case 'h':
            case '?':
            default:
                usage();
                exit(1);
                break;
        }
    }

    if(dname == NULL)
    {
        fprintf(stderr, "no domain name specified, exiting...\n");
        exit(1);
    }

    getkeyviadane(dname, GETDNS_RRTYPE_TLSA, &certtxt);

    printf("certificate text:\n%s\n", certtxt);

    if(certtxt)
        free(certtxt);

    return 0;
} /* main */

/* getdns_dane_encode.c */
