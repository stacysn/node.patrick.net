-- created with "mysqldump -d -ukillelea -p$mysql_password killelea" 
--
-- MySQL dump 10.13  Distrib 5.5.40-36.1, for debian-linux-gnu (i686)
--
-- Host: localhost    Database: killelea
-- ------------------------------------------------------
-- Server version	5.5.40-36.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `badwords`
--

DROP TABLE IF EXISTS `badwords`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `badwords` (
  `badword_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `badword_content` varchar(100) NOT NULL,
  PRIMARY KEY (`badword_id`),
  UNIQUE KEY `badword_content` (`badword_content`)
) ENGINE=MyISAM AUTO_INCREMENT=85 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `comments` (
  `comment_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `comment_post_id` bigint(20) unsigned NOT NULL,
  `comment_date` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `comment_content` text NOT NULL,
  `comment_likes` int(11) NOT NULL,
  `comment_dislikes` int(11) NOT NULL,
  `comment_approved` tinyint(4) DEFAULT NULL,
  `comment_author` bigint(20) DEFAULT NULL,
  `comment_adhom_reporter` bigint(20) unsigned DEFAULT NULL,
  `comment_adhom_when` datetime DEFAULT NULL,
  PRIMARY KEY (`comment_id`),
  KEY `comment_approved` (`comment_approved`),
  KEY `comment_post_ID` (`comment_post_id`),
  KEY `user_ID_index` (`comment_author`),
  KEY `comment_karma_index` (`comment_likes`),
  FULLTEXT KEY `comment_content_index` (`comment_content`)
) ENGINE=MyISAM AUTO_INCREMENT=1405371 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `commentvotes`
--

DROP TABLE IF EXISTS `commentvotes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `commentvotes` (
  `commentvote_user_id` bigint(20) unsigned NOT NULL,
  `commentvote_comment_id` bigint(20) unsigned NOT NULL,
  `commentvote_up` bigint(20) unsigned NOT NULL DEFAULT '0',
  `commentvote_down` bigint(20) unsigned NOT NULL DEFAULT '0',
  UNIQUE KEY `uniqueness` (`commentvote_user_id`,`commentvote_comment_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `countries`
--

DROP TABLE IF EXISTS `countries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `countries` (
  `country_name` varchar(40) NOT NULL,
  `country_registry` varchar(20) NOT NULL,
  `country_start` bigint(20) unsigned NOT NULL,
  `country_end` bigint(20) unsigned NOT NULL,
  `country_assigned` bigint(20) unsigned NOT NULL,
  `country_evil` bigint(20) unsigned NOT NULL DEFAULT '0',
  KEY `country_start_index` (`country_start`),
  KEY `country_end_index` (`country_end`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ips`
--

DROP TABLE IF EXISTS `ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ips` (
  `ip_user_id` bigint(20) unsigned NOT NULL,
  `ip_addr` varchar(16) NOT NULL,
  `ip_ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `uniqueness` (`ip_user_id`,`ip_addr`),
  KEY `user_ID_index` (`ip_user_id`),
  KEY `user_ip_index` (`ip_addr`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `nukes`
--

DROP TABLE IF EXISTS `nukes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `nukes` (
  `nuke_date` datetime NOT NULL,
  `nuke_email` varchar(100) DEFAULT NULL,
  `nuke_username` varchar(250) DEFAULT NULL,
  `nuke_ip` varchar(16) NOT NULL,
  `nuke_country` varchar(40) DEFAULT NULL,
  UNIQUE KEY `ip_address` (`nuke_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `onlines`
--

DROP TABLE IF EXISTS `onlines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `onlines` (
  `online_user_id` bigint(20) unsigned NOT NULL,
  `online_username` varchar(16) NOT NULL,
  `online_last_view` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`online_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `posts`
--

DROP TABLE IF EXISTS `posts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `posts` (
  `post_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) NOT NULL DEFAULT '0',
  `post_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `post_content` text NOT NULL,
  `post_title` varchar(255) DEFAULT NULL,
  `post_modified` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `post_comments` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_views` int(11) NOT NULL DEFAULT '0',
  `post_likes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_dislikes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_latest_comment_id` bigint(20) unsigned DEFAULT NULL,
  `post_latest_commenter_id` bigint(20) unsigned DEFAULT NULL,
  `post_latest_comment_excerpt` varchar(1240) DEFAULT NULL,
  `post_approved` tinyint(3) unsigned DEFAULT NULL,
  `post_referers` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_nsfw` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_topic` varchar(32) NOT NULL DEFAULT '',
  `post_private` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`post_id`),
  UNIQUE KEY `post_title` (`post_title`),
  KEY `post_author_index` (`post_author`),
  KEY `thread_approved_index` (`post_approved`),
  KEY `post_date_index` (`post_date`),
  KEY `post_modified_index` (`post_modified`),
  KEY `post_topic_index` (`post_topic`),
  KEY `post_private_index` (`post_private`),
  FULLTEXT KEY `post_title_content_index` (`post_title`,`post_content`)
) ENGINE=MyISAM AUTO_INCREMENT=1305627 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `postviews`
--

DROP TABLE IF EXISTS `postviews`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `postviews` (
  `postview_user_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `postview_post_id` bigint(20) unsigned NOT NULL DEFAULT '0',
  `postview_last_view` datetime DEFAULT NULL,
  `postview_want_email` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`postview_user_id`,`postview_post_id`),
  KEY `post_ID_index` (`postview_post_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `postvotes`
--

DROP TABLE IF EXISTS `postvotes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `postvotes` (
  `postvote_user_id` bigint(20) unsigned NOT NULL,
  `postvote_post_id` bigint(20) unsigned NOT NULL,
  `postvote_up` bigint(20) unsigned NOT NULL DEFAULT '0',
  `postvote_down` bigint(20) unsigned NOT NULL DEFAULT '0',
  UNIQUE KEY `uniqueness` (`postvote_user_id`,`postvote_post_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `referers`
--

DROP TABLE IF EXISTS `referers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `referers` (
  `referer_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `referer_ts` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `referer_author_id` bigint(20) unsigned DEFAULT NULL,
  `referer_post_id` bigint(20) unsigned DEFAULT NULL,
  `referer_url` varchar(256) DEFAULT NULL,
  `referer_usage_count` bigint(20) unsigned DEFAULT '1',
  PRIMARY KEY (`referer_id`),
  UNIQUE KEY `uniqueness` (`referer_post_id`,`referer_url`),
  KEY `inbound_links_author_ID` (`referer_author_id`),
  KEY `inbound_links_post_ID` (`referer_post_id`)
) ENGINE=InnoDB AUTO_INCREMENT=148755 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `relationships`
--

DROP TABLE IF EXISTS `relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `relationships` (
  `rel_self_id` bigint(20) unsigned NOT NULL,
  `rel_other_id` bigint(20) unsigned NOT NULL,
  `rel_my_friend` bigint(20) unsigned NOT NULL DEFAULT '0',
  `rel_i_ban` bigint(20) unsigned NOT NULL DEFAULT '0',
  `rel_i_follow` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`rel_self_id`,`rel_other_id`),
  KEY `other_ID_index` (`rel_other_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `shares`
--

DROP TABLE IF EXISTS `shares`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `shares` (
  `share_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `share_sender` bigint(20) unsigned NOT NULL,
  `share_url` varchar(255) NOT NULL,
  `share_title` varchar(255) NOT NULL,
  `share_mailto` varchar(100) NOT NULL,
  `share_created` datetime DEFAULT NULL,
  `share_sent` datetime DEFAULT NULL,
  `share_version` int(11) DEFAULT NULL,
  `share_ip` varchar(16) DEFAULT NULL,
  `share_comment` text,
  PRIMARY KEY (`share_id`),
  KEY `share_sender_index` (`share_sender`),
  KEY `share_ip_index` (`share_ip`)
) ENGINE=MyISAM AUTO_INCREMENT=3194 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `topicwatches`
--

DROP TABLE IF EXISTS `topicwatches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `topicwatches` (
  `topicwatch_name` varchar(32) NOT NULL,
  `topicwatch_user_id` bigint(20) unsigned NOT NULL,
  `topicwatch_start` datetime DEFAULT NULL,
  UNIQUE KEY `uniqueness` (`topicwatch_name`,`topicwatch_user_id`),
  KEY `topic_follows_topic_index` (`topicwatch_name`),
  KEY `topic_follows_user_ID_index` (`topicwatch_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `user_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_pass` varchar(64) NOT NULL DEFAULT '',
  `user_email` varchar(100) DEFAULT NULL,
  `user_url` varchar(100) NOT NULL DEFAULT '',
  `user_registered` datetime DEFAULT NULL,
  `user_activation_key` varchar(60) DEFAULT NULL,
  `user_name` varchar(250) DEFAULT NULL,
  `user_last_comment_time` datetime DEFAULT NULL,
  `user_icon` varchar(160) DEFAULT NULL,
  `user_posts` int(11) unsigned DEFAULT '0',
  `user_comments` int(11) unsigned DEFAULT '0',
  `user_zip` varchar(5) DEFAULT NULL,
  `user_last_comment_ip` varchar(16) DEFAULT NULL,
  `user_want_newsletter` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_level` bigint(20) DEFAULT '1',
  `user_friends` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_summonable` bigint(20) unsigned NOT NULL DEFAULT '1',
  `user_icon_width` bigint(20) DEFAULT NULL,
  `user_icon_height` bigint(20) DEFAULT NULL,
  `user_likes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_dislikes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_followers` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_bannedby` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_aboutyou` text,
  `user_pbias` bigint(20) NOT NULL DEFAULT '0',
  `user_suspended_until` datetime DEFAULT NULL,
  `user_country` varchar(40) DEFAULT NULL,
  `user_hide_post_list_photos` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_referers` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_civil_comments` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_adhom_comments` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_realname` varchar(250) DEFAULT NULL,
  `user_banning` bigint(20) unsigned NOT NULL DEFAULT '0',
  `user_timezone` varchar(80) NOT NULL DEFAULT 'America/Los_Angeles',
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `unique_key` (`user_activation_key`),
  UNIQUE KEY `display_name` (`user_name`),
  UNIQUE KEY `email` (`user_email`),
  KEY `zip_index` (`user_zip`),
  KEY `user_comments_index` (`user_comments`),
  KEY `last_comment_ip_index` (`user_last_comment_ip`),
  KEY `realname_index` (`user_realname`)
) ENGINE=MyISAM AUTO_INCREMENT=126719 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `whitelists`
--

DROP TABLE IF EXISTS `whitelists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `whitelists` (
  `whitelist_post_id` bigint(20) unsigned NOT NULL,
  `whitelist_user_id` bigint(20) unsigned NOT NULL,
  `whitelist_user_added_by` bigint(20) unsigned NOT NULL,
  `whitelist_when_user_added` datetime NOT NULL,
  UNIQUE KEY `uniqueness` (`whitelist_post_id`,`whitelist_user_id`),
  KEY `post_whitelists_post_ID_index` (`whitelist_post_id`),
  KEY `post_whitelists_user_ID_index` (`whitelist_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-05-18 21:48:43
