Summary: PAM cached credentials module
Name: pam_ccreds
Version: 2
Release: 1
Source0: ftp://ftp.padl.com/pub/%{name}-%{version}.tar.gz
URL: http://www.padl.com/
Copyright: GPL
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-root
Requires: openssl
Obsoletes: pam_ccreds

%description
The pam_ccreds module provides a mechanism for caching
credentials when authenticating against a network
authentication service so that authentication can still
proceed when the service is down. 

%prep
%setup -q -a 0

%build
./configure
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc,lib/security}

install -m 755 pam_ccreds.so $RPM_BUILD_ROOT/lib/security/

chmod 755 $RPM_BUILD_ROOT/lib/security/pam_ccreds.so

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /lib/security/pam_ccreds.so
%doc AUTHORS NEWS COPYING README ChangeLog

%changelog

