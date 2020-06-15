#include <stdio.h>
#include <src/fetch_util.h>
#include <src/util.h>

XML_DATA *new_snapshot_xml_data(char *uri, OPTS *opts);
int apply_basedir_working_snapshot(XML_DATA *xml_data);
