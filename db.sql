CREATE TABLE `user_access_tokens` (
  `access_token` varchar(40) NOT NULL,
  PRIMARY KEY (`access_token`),
  `client_id` varchar(80) NOT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `auth_clients` (
  `client_id` varchar(80) NOT NULL,
  PRIMARY KEY (`client_id`),
  `client_secret` varchar(80) DEFAULT NULL,
  `redirect_uri` varchar(2000) NOT NULL,
  `grant_types` varchar(80) DEFAULT NULL,
  `scope` varchar(100) DEFAULT NULL,
  `user_id` varchar(80) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `user_refresh_tokens` (
  `refresh_token` varchar(40) NOT NULL,
  PRIMARY KEY (`refresh_token`),
  `client_id` varchar(80) NOT NULL,
  `user_id` varchar(255) DEFAULT NULL,
  `expires` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `scope` varchar(2000) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  `permission` varchar(200) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  `email` varchar(255) NOT NULL,
  `password` varchar(2000) DEFAULT NULL,
  `firstname` varchar(255) DEFAULT NULL,
  `lastname` varchar(255) DEFAULT NULL,
  `created` datetime NOT NULL,
  `activated` tinyint(1) NOT NULL,
  `activationcode` varchar(128) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `user_password_reset_requests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`),
  `user_id` int(11) NOT NULL,
  `code` varchar(128) NOT NULL,
  `expires` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `user_permissions` (
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
