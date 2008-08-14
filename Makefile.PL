use inc::Module::Install;

name    'Form-Security-Token';

perl_version        '5.006';
all_from 'lib/Form/Sec/Token.pm';

requires            'Carp'              => 0;
requires            'Data::GUID';
requires            'Digest::SHA1';

build_requires      'Test::More'        => '0.7';
build_requires      'Test::MockModule'  => 0;

auto_install;
WriteAll;
