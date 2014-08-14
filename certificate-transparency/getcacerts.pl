#! /usr/bin/perl

use strict;

use JSON;
use LWP;
use MIME::Base64;
use DBI;
use Digest;
use Switch 'Perl6';

my $ua = LWP::UserAgent->new;
my $CTLOG = "http://ct.googleapis.com/aviator";
my $sha256 = Digest->new("SHA-256");
my ($db, %cacerts, $largestentrynumber, $logentries);

my $boringentry = 1;
my $interestingentry = 4028324;

sub init {
  $db = DBI->connect("DBI:SQLite:dbname=certs.db");
  %cacerts = getcacerts();
}

sub deinit {
  $db->disconnect;
}

sub fetchroots {
  my $response;
  my $roots;

  $response = $ua->get("$CTLOG/ct/v1/get-roots");
  if ($response->is_success)
  {
    $roots = from_json($response->content);
  }
  return @{$roots->{certificates}};
}

sub fetchnumberofentries {
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

sub fetchentry {
  my ($entrynumber) = @_;
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

sub decodeASN1Cert {
  my ($content) = @_;
  my %res;
  my ($len, $v1, $v2);

  ($v1, $v2) = unpack("Cn", $$content);
  substr $$content, 0, 3, "";
  $len = ($v1<<16)+$v2;
  $res{certificate} = substr($$content, 0, $len);
  substr $$content, 0, $len, "";

  return %res;
}

sub decodePreCert {
  my ($content) = @_;
  my %res;
  my ($len, $v1, $v2);

  $res{issuer_key_hash} = substr($$content, 0, 32);
  substr $$content, 0, 32, "";

  ($v1, $v2) = unpack("Cn", $$content);
  substr $$content, 0, 3, "";
  $len = ($v1<<16)+$v2;
  $res{tbs_certificate} = substr($$content, 0, $len);
  substr $$content, 0, $len, "";

  return %res;
}

sub decodeCtExtensions {
  my ($content) = @_;
  my %res;
  my ($len);

  $len = unpack("n", $$content);
  substr $$content, 0, 2, "";
  $res{extensions} = substr($$content, 0, $len);
  substr $$content, 0, $len, "";

  return %res;
}

sub decodeTimestampedEntry {
  my ($content) = @_;
  my %res;
  my ($v1, $v2, %res2, %res3);

  ($v1, $v2) = unpack("NN", $$content);
  $res{timestamp} = ($v1<<32) + $v2;
  substr $$content, 0, 8, "";
  $res{entry_type} = unpack("n", $$content);
  substr $$content, 0, 2, "";

  given ($res{entry_type}) {
    when 0 { %res2 = decodeASN1Cert($content); $res{signed_entry} = \%res2; }
    when 1 { %res2 = decodePreCert($content); $res{signed_entry} = \%res2; }
  }

  %res3 = decodeCtExtensions($content);
  $res{extensions} = \%res3;

  return %res;
}

sub decodeMerkleTreeLeaf {
  my ($content) = @_;
  my %res;
  my %res2;

  $res{version} = unpack("C", $$content);
  substr $$content, 0, 1, "";
  $res{leaf_type} = unpack("C", $$content);
  substr $$content, 0, 1, "";
  %res2 = decodeTimestampedEntry($content);
  $res{timestamped_entry} = \%res2;

  return %res;
}

sub fetchdecodedentry {
  my ($entrynumber) = @_;
  my ($response, $entry, %decodedentry, $content);

  $response =
  $ua->get("$CTLOG/ct/v1/get-entries?start=$entrynumber&end=$entrynumber");
  if ($response->is_success)
  {
    $entry = from_json($response->content);
  }
  $content = decode_base64($entry->{entries}[0]{leaf_input});
  %decodedentry = decodeMerkleTreeLeaf(\$content);
  return %decodedentry;
}

sub fetchentries {
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
  my $nb2;

  $sth = $db->prepare("SELECT distinct entryid from certs order by entryid desc limit 1");
  $sth->execute();
  $nb2 = $sth->fetchrow_array;
  $nb = $nb2 if (defined $nb2);
  $sth->finish;
  return $nb;
}

sub getcacerts {
  my $sth;
  my %cacerts;
  my ($certhash, $certid);

  # Retourne un hash hashé->certid
  $sth = $db->prepare("SELECT certhash, certid from cacerts");
  $sth->execute();
  while (($certhash, $certid) = $sth->fetchrow_array)
  {
    $cacerts{$certhash} = $certid;
  }
  $sth->finish;
  return %cacerts;
}

sub importrootcert {
  my ($cert) = @_;
  my $sth;
  my $dgst;
  my $certid = 0;
  my $requestedcertid;

  $dgst = $sha256->add(decode_base64($cert))->hexdigest;

  $sth = $db->prepare("SELECT certid from cacerts order by certid desc limit 1");
  $sth->execute();
  $requestedcertid = $sth->fetchrow_array;
  $certid = $requestedcertid if defined $requestedcertid;
  $certid++;
  $sth = $db->prepare("INSERT into cacerts(certid, issuerid, certdata, certhash) values (?, ?, ?, ?)");
  $sth->execute($certid, $certid, $cert, $dgst);
  $sth->finish;
  return $certid;
}

sub updateroots {
  my @logroots = fetchroots();

  foreach my $root (@logroots) {
    my $dgst = $sha256->add(decode_base64($root))->hexdigest;
    if (!defined $cacerts{$dgst})
    {
      my $certid = importrootcert($root);
      $cacerts{$dgst} = $certid;
    }
  }
}

print "Initializing stuff\n";
init();

print "Updating list of root certificates\n";
updateroots();

$largestentrynumber = getlargestlocalentry();
$logentries = fetchnumberofentries();
print "Log has $logentries entries, local DB goes up to $largestentrynumber\n";

my $entry = fetchentry($boringentry);
print to_json($entry, { pretty => 1 });

my $entry = fetchentry($interestingentry);
print to_json($entry, { pretty => 1 });

my %entry = fetchdecodedentry($boringentry);
print to_json(\%entry, { pretty => 1 });

my %entry = fetchdecodedentry($interestingentry);
print to_json(\%entry, { pretty => 1 });

# Read greatest entry from DB.certs
# Ask for greatest entry from log
# While there's more log entries to fetch
#   Fetch a bunch of entries
#   For each entry received: decode leaf_input, decode extra_data, insert unknown extra_data certs into DB.cacerts and memory, replace extra_data by corresponding DB.certids, insert leaf_input into DB.certs

#$perl_scalar = from_json( $json_text, { utf8  => 1 } );
#$json_text   = to_json( $perl_scalar, { ascii => 1, pretty => 1 } );

#print fetchnumberofentries(), "\n";
#print getlargestlocalentry(), "\n";
#print to_json(getlogroots(), { pretty => 1 }), "\n";

#my $entry = getentry(1);
#print to_json($entry, { pretty => 1 }), "\n";
#print $$entry{entries}[0]{leaf_input}, "\n";
#print $$entry{entries}[0]{extra_data}, "\n";
#$decoded = decode_base64($encoded);

#my $entries = getentries(1, 2);
#print to_json($entries, { pretty => 1 }), "\n";

deinit();
