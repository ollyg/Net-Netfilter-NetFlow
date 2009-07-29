use inc::Module::Install 0.67;
perl_version '5.008001';
  
name        'Net-Netfilter-NetFlow';
all_from    'script/nfflowd';

requires    'Config'              => 0;
requires    'POSIX'               => 0;
requires    'Exporter'            => 0;
requires    'Time::HiRes'         => 0;
requires    'Getopt::Long'        => 0;
requires    'File::Spec'          => 0;
requires    'ExtUtils::MakeMaker' => 0;

requires    'Log::Dispatch::Configurator::Any' => '1.0005';
requires    'Daemon::Generic' => 0;
requires    'File::Slurp'     => '9999.06';
requires    'IPC::Run'        => 0;
requires    'Config::Any'     => '0.15';
requires    'Config::General' => 0;

test_requires  'Test::More' => 0;
test_requires  'Test::Pod'  => 0;
test_requires  'Test::Pod::Coverage' => 0;

install_share;
install_script  'script/nfflowd';

WriteAll;

