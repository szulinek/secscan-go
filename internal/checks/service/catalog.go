package service

import (
	"secscan/internal/checks"
)

func DefaultModules() []checks.Module {
	return []checks.Module{
		New(Definition{
			ID:        "directadmin",
			Name:      "DirectAdmin",
			Service:   "directadmin",
			Category:  checks.CategoryCompliance,
			UnitNames: []string{"directadmin.service"},
			DetectPaths: []string{
				"/usr/local/directadmin/directadmin",
				"/usr/local/directadmin/conf/directadmin.conf",
			},
		}),
		New(Definition{
			ID:        "mysql_mariadb",
			Name:      "MySQL / MariaDB",
			Service:   "mysql/mariadb",
			Category:  checks.CategoryDatabase,
			UnitNames: []string{"mysql.service", "mariadb.service", "mysqld.service"},
			DetectPaths: []string{
				"/usr/sbin/mysqld",
				"/usr/local/mysql/bin/mysqld",
				"/etc/mysql/my.cnf",
				"/etc/my.cnf",
			},
		}),
		New(Definition{
			ID:        "exim",
			Name:      "Exim",
			Service:   "exim",
			Category:  checks.CategoryMail,
			UnitNames: []string{"exim.service", "exim4.service"},
			UnitGlobs: []string{"exim*.service"},
			DetectPaths: []string{
				"/usr/sbin/exim",
				"/usr/sbin/exim4",
				"/etc/exim.conf",
				"/etc/exim",
				"/etc/exim4",
			},
		}),
		New(Definition{
			ID:        "dovecot",
			Name:      "Dovecot",
			Service:   "dovecot",
			Category:  checks.CategoryMail,
			UnitNames: []string{"dovecot.service"},
			DetectPaths: []string{
				"/usr/sbin/dovecot",
				"/etc/dovecot.conf",
				"/etc/dovecot/dovecot.conf",
			},
		}),
		New(Definition{
			ID:        "redis",
			Name:      "Redis",
			Service:   "redis",
			Category:  checks.CategoryCache,
			UnitNames: []string{"redis.service", "redis-server.service"},
			UnitGlobs: []string{"redis*.service"},
			DetectPaths: []string{
				"/usr/bin/redis-server",
				"/etc/redis/redis.conf",
			},
		}),
		New(Definition{
			ID:        "named_bind",
			Name:      "Named / BIND",
			Service:   "named/bind",
			Category:  checks.CategorySystem,
			UnitNames: []string{"named.service", "bind9.service", "named-chroot.service"},
			DetectPaths: []string{
				"/usr/sbin/named",
				"/etc/bind/named.conf",
				"/etc/named.conf",
			},
		}),
		New(Definition{
			ID:        "pure_ftpd",
			Name:      "Pure-FTPd",
			Service:   "pure-ftpd",
			Category:  checks.CategorySystem,
			UnitNames: []string{"pure-ftpd.service", "pure-ftpd-mysql.service"},
			UnitGlobs: []string{"pure-ftpd*.service"},
			DetectPaths: []string{
				"/usr/sbin/pure-ftpd",
				"/etc/pure-ftpd.conf",
				"/etc/pure-ftpd",
			},
		}),
		New(Definition{
			ID:       "firewall_csf_lfd",
			Name:     "Firewall / CSF-LFD",
			Service:  "firewall/csf-lfd",
			Category: checks.CategoryFirewall,
			UnitNames: []string{
				"csf.service",
				"lfd.service",
				"nftables.service",
				"firewalld.service",
			},
			DetectPaths: []string{
				"/etc/csf/csf.conf",
				"/usr/sbin/csf",
				"/usr/sbin/lfd",
			},
		}),
	}
}
