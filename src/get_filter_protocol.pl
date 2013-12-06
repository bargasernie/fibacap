#!/usr/bin/perl

use strict;
use warnings;


sub get_header_file {
	my $PROTOCOL = shift @_;
	my $uc_PROTOCOL = uc $PROTOCOL;
	my $text = "";

	$text = qq|
#ifndef	_FBC_FILTER_$uc_PROTOCOL\_H_
#define _FBC_FILTER_$uc_PROTOCOL\_H_

#include "fbc_packet.h"
#include "fbc_filter.h"
#include "fbc_pf.h"

/* Filter attribute map */
fbc_add_func_into_filter_t fbc_$PROTOCOL\_attribute_map(char *attr);

#endif
|;
	return $text;
}

sub get_attribute_map {
	my $PROTOCOL = shift @_;
	my $attrlist = shift @_;
	my $text = "";

	$text = qq|
/* $PROTOCOL attribute map */
|;
	
	#
	# Attribute
	#
	for my $a (@$attrlist) {
		my $ATTRIBUTE = $a->{ATTRIBUTE};
		$text .= qq|int fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func(fbc_Filter *filter, char *attr, char *value);
|;
	}

	$text .= qq|
static struct fbc_attribute_map_list fbc_$PROTOCOL\_attribute[32] = {
|;

	#
	# Attribute
	#
	for my $a (@$attrlist) {
		my $ATTRIBUTE = $a->{ATTRIBUTE};
		$text .= qq|	{ "$ATTRIBUTE", fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func },
|;
	}

	#
	#
	#
	$text .= qq|	{ FBC_ATTRIBUTE_NULL, 0, }
};

|;

	return $text;
}

sub get_filter_function {
	my $PROTOCOL = shift @_;
	my $arg = shift @_;
	my $text = "";

	# when need to use memcpy to compare
	# $PROTOCOL
	# $ATTRIBUTE
	# $ATTRIBUTE_INFO
	# $STRUCT
	# $STRUCT_ATTRIBUTE
	#
	my $ATTRIBUTE = $arg->{ATTRIBUTE};
	my $ATTRIBUTE_INFO = $arg->{ATTRIBUTE_INFO};
	my $STRUCT = $arg->{STRUCT};
	my $STRUCT_ATTRIBUTE = $arg->{STRUCT_ATTRIBUTE};
	my $ARG_VAR = $arg->{ARG_VAR};
	my $ARG_TYPE = $arg->{ARG_TYPE};
	my $ARG_SIZE = $arg->{ARG_SIZE};
	my $TYPE = $arg->{TYPE};

	if ($TYPE eq "array") {
		$text = qq|
/* filter function */
/* fbc_filter_func_t */
int fbc_filter_$PROTOCOL\_$ATTRIBUTE(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	$ARG_TYPE *$ARG_VAR = ($ARG_TYPE *)&((($STRUCT *)packet->header)->$STRUCT_ATTRIBUTE);
	DPRINTF("-DEBUG- fbc_filter_$PROTOCOL\_$ATTRIBUTE:\\tmatching $PROTOCOL $ATTRIBUTE_INFO\\n");
	return (memcmp($ATTRIBUTE, arg, arg_size) == 0);
}
|;
	} 

	if (($TYPE eq "u_int16_t")
	or  ($TYPE eq "u_int32_t")
	or  ($TYPE eq "u_int8_t" )
	or  ($TYPE eq "Byte"     )
	or  ($TYPE eq "bits"     )
	) {
		$text = qq|
/* filter function */
/* fbc_filter_func_t */
int fbc_filter_$PROTOCOL\_$ATTRIBUTE(fbc_Packet *packet, fbc_filter_arg_t arg, int arg_size)
{
	$ARG_TYPE $ARG_VAR = ($ARG_TYPE)((($STRUCT *)packet->header)->$STRUCT_ATTRIBUTE);
	DPRINTF("-DEBUG- fbc_filter_$PROTOCOL\_$ATTRIBUTE:\\tmatching $PROTOCOL $ATTRIBUTE_INFO\\n");
	return ($ARG_VAR == *($ARG_TYPE *)arg);
}
|;
	}
	
	return $text;
}

sub get_fbc_filter_add_function {
	my $PROTOCOL = shift @_;
	my $arg = shift @_;
	my $text = "";

	# when $TYPE is array
	# $ATTRIBUTE
	# $ARG_TYPE
	# $ARG_VAR
	# $ARG_SIZE
	
	my $ATTRIBUTE = $arg->{ATTRIBUTE};
	my $ARG_TYPE = $arg->{ARG_TYPE};
	my $ARG_VAR = $arg->{ARG_VAR};
	my $ARG_SIZE = $arg->{ARG_SIZE};
	my $TYPE = $arg->{TYPE};

	if ($TYPE eq "array") {
		$text = qq|
/* function that adds filter function into filter */
/* fbc_add_func_into_filter_t */
int fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	$ARG_TYPE $ARG_VAR\[$ARG_SIZE];
	DPRINTF2("-DEBUG- fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func: <%s>=<%s>\\n", attr, value);

	/* XXX TODO: fill the ARG_VAR */
	printf("********************************\\n");
	printf("***** YOU NEED TO FIX HERE *****\\n");
	printf("********************************\\n");

	fbc_filter_add_func(filter, fbc_filter_$PROTOCOL\_$ATTRIBUTE, $ARG_VAR, sizeof($ARG_VAR));
	DPRINTF("-DEBUG- fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func: add fbc_filter_$PROTOCOL\_$ATTRIBUTE into filter\\n");
	return 1;
}
|;
	}

	if (($TYPE eq "u_int16_t") 
	or  ($TYPE eq "u_int32_t") 
	or  ($TYPE eq "u_int8_t" )
	or  ($TYPE eq "bits"     )
	or  ($TYPE eq "Byte"     )) {
		$text = qq|
/* function that adds filter function into filter */
/* fbc_add_func_into_filter_t */
int fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func(fbc_Filter *filter, char *attr, char *value)
{
	$ARG_TYPE $ARG_VAR;
	DPRINTF2("-DEBUG- fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func: <%s>=<%s>\\n", attr, value);|;

		if ($ARG_TYPE eq "u_int16_t") {
			$text .= qq|
	$ARG_VAR = htons(($ARG_TYPE)string_to_uint(value));|;
		} elsif ($ARG_TYPE eq "u_int32_t") {
			$text .= qq|
	$ARG_VAR = htonl(($ARG_TYPE)string_to_uint(value));|;
		} else {
			$text .= qq|
	$ARG_VAR = ($ARG_TYPE)string_to_uint(value);|;
		}

		$text .= qq|
	fbc_filter_add_func(filter, fbc_filter_$PROTOCOL\_$ATTRIBUTE, &$ARG_VAR, sizeof($ARG_VAR));
	DPRINTF("-DEBUG- fbc_filter_$PROTOCOL\_add_$ATTRIBUTE\_filter_func: add fbc_filter_$PROTOCOL\_$ATTRIBUTE into filter\\n");
	return 1;
}
|;
	}

	return $text;
}

sub get_attribute_map_function {
	# $PROTOCOL
	my $PROTOCOL = shift @_;
	my $uc_PROTOCOL = uc $PROTOCOL;
	my $text = "";

	$text = qq|
/*
 * 5. attribute map function
 */

fbc_add_func_into_filter_t fbc_$PROTOCOL\_attribute_map(char *attr)
{
	int i = 0;
	while (1) {
		if (fbc_attribute_equal(fbc_$PROTOCOL\_attribute[i].attribute, attr)) {
			return (fbc_$PROTOCOL\_attribute[i].add_func_into_filter);
		}
		if (fbc_attribute_equal(fbc_$PROTOCOL\_attribute[i].attribute, FBC_ATTRIBUTE_NULL)) {
			fprintf(stderr, "No attribute %s in protocol %s\\n", attr, FBC_PROTOCOL_$uc_PROTOCOL);
			return 0;
		}
		i++;
	}
	return 0;
}
|;
	return $text;
}

sub write_to_file {
	my $file = shift @_;
	my $context = shift @_;
	my $time = localtime."";
	my $header = qq|/* This file is created by $0, @ $time.
 * ------ chhquan.
 */
	|;
	open FILE, ">", $file;
	print FILE $header;
	print FILE $context;
	close FILE;
}
###############################################

my $hf = "";
my $cf = "";
my $PROTOCOL = "tcp";
my $hf_name = "fbc_filter_$PROTOCOL.h";
my $cf_name = "fbc_filter_$PROTOCOL.c";
my @attr = ();

my %hash1 = (
	ATTRIBUTE => "sport",
	ATTRIBUTE_INFO => "source port",
	TYPE => "u_int16_t",
	STRUCT => "struct tcphdr",
	STRUCT_ATTRIBUTE => "source",
	ARG_TYPE => "u_int16_t",
	ARG_VAR => "sport",
	ARG_SIZE => "sizeof(u_int16_t)",
);

push @attr, \%hash1;


my %hash2 = (
	ATTRIBUTE => "dport",
	ATTRIBUTE_INFO => "destination port",
	TYPE => "u_int16_t",
	STRUCT => "struct tcphdr",
	STRUCT_ATTRIBUTE => "dest",
	ARG_TYPE => "u_int16_t",
	ARG_VAR => "dport",
	ARG_SIZE => "sizeof(u_int16_t)",
);

push @attr, \%hash2;


$hf = &get_header_file($PROTOCOL);

$cf = qq|
/* include file */
#include "fbc_filter_$PROTOCOL.h"
#include "fbc_pf.h"

/* If you want to add an protocol be filtered, there are several parts:
 *
 * 	1. attribute of the protocol
 * 	2. filter function
 * 	3. function that adds filter function into filter
 * 	4. attribute map
 * 	5. attribute map function
 */

/* 
 * 4. attribute map
 */
|;

$cf .= &get_attribute_map($PROTOCOL, \@attr);
$cf .= qq|
/**
 * 2. filter function
 *
 */
|;

for my $a (@attr) {
	$cf .= &get_filter_function($PROTOCOL, $a);
}

$cf .= qq|
/*
 * 3. function that adds filter function into filter 
 */
|;

for my $a (@attr) {
	$cf .= &get_fbc_filter_add_function($PROTOCOL, $a);
}

$cf .= &get_attribute_map_function($PROTOCOL);

&write_to_file($hf_name, $hf);
&write_to_file($cf_name, $cf);
