#! /usr/bin/perl

use JSON;
use LWP;
use MIME::Base64;
use DBI;

my $ua = LWP::UserAgent->new;
my $CTLOG = "http://ct.googleapis.com/aviator";
my $db;

# CTLOG BASEURL: http://ct.googleapis.com/aviator
# Get latest STH
# GET BASEURL/ct/v1/get-sth
# Get a bunch of entries
# GET BASEURL/ct/v1/get-entries?start=0&end=1

sub init {
  $db = DBI->connect("DBI:SQLite:dbname=certs.db");
}

sub deinit {
  $db->disconnect;
}

sub getnumberofentriesinctlog {
  my $response;
  my $sth;
  my $number = 0;

  $response = $ua->get("$CTLOG/ct/v1/get-sth");
  if ($response->is_success)
  {
    $sth = from_json($response->content);
    $number = $$sth{tree_size};
  }
  return $number;
}

sub getentry {
  my $entrynumber = @_;
  my $response;
  my $entry;

  $response =
  $ua->get("$CTLOG/ct/v1/get-entries?start=$entrynumber&end=$entrynumber");
  if ($response->is_success)
  {
    $entry = from_json($response->content);
  }
  return $entry;
}

sub getentries {
  my ($start, $end) = @_;
  my $response;
  my $entries;

  $response =
  $ua->get("$CTLOG/ct/v1/get-entries?start=$start&end=$end");
  if ($response->is_success)
  {
    $entries = from_json($response->content);
  }
  return $entries;
}

sub getlargestlocalentry {
  my $sth;
  my $nb= -1;

  $sth = $db->prepare("SELECT distinct entryid from certs order by entryid desc limit 1");
  $sth->execute();
  if ($sth->rows)
  {
    $nb = $sth->fetchrow_array;
  }
  $sth->finish;
  return $nb;
}

init();
deinit();

#$perl_scalar = from_json( $json_text, { utf8  => 1 } );
#$json_text   = to_json( $perl_scalar, { ascii => 1, pretty => 1 } );

print getnumberofentriesinctlog(), "\n";
print getlargestlocalentry(), "\n";
#my $entry = getentry(1);
#print to_json($entry, { pretty => 1 }), "\n";
#print $$entry{entries}[0]{leaf_input}, "\n";
#print $$entry{entries}[0]{extra_data}, "\n";
#$decoded = decode_base64($encoded);

#my $entries = getentries(1, 2);
#print to_json($entries, { pretty => 1 }), "\n";
