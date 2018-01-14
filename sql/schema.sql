-- create with: mysqldump -d -ukillelea -p$mysql_password killelea
-- MySQL dump 10.13  Distrib 5.7.13, for osx10.11 (x86_64)
--
-- Host: localhost    Database: killelea
-- ------------------------------------------------------
-- Server version	5.7.13

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
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `comments` (
  `comment_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `comment_post_id` bigint(20) unsigned NOT NULL,
  `comment_date` datetime DEFAULT '1970-01-01 00:00:00',
  `comment_content` mediumtext NOT NULL,
  `comment_likes` bigint(20) unsigned DEFAULT '0',
  `comment_dislikes` bigint(20) unsigned DEFAULT '0',
  `comment_approved` tinyint(4) DEFAULT NULL,
  `comment_author` bigint(20) DEFAULT NULL,
  `comment_adhom_reporter` bigint(20) unsigned DEFAULT NULL,
  `comment_adhom_when` datetime DEFAULT NULL,
  PRIMARY KEY (`comment_id`),
  KEY `comment_approved` (`comment_approved`),
  KEY `comment_post_ID` (`comment_post_id`),
  KEY `user_ID_index` (`comment_author`),
  KEY `comment_karma_index` (`comment_likes`),
  KEY `uncivil_index` (`comment_adhom_when`),
  FULLTEXT KEY `comment_content_index` (`comment_content`)
) ENGINE=MyISAM AUTO_INCREMENT=1474786 DEFAULT CHARSET=utf8mb4;
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `lurkers`
--

DROP TABLE IF EXISTS `lurkers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `lurkers` (
  `lurker_username` varchar(40) NOT NULL,
  `lurker_last_view` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`lurker_username`)
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `onlines`
--

DROP TABLE IF EXISTS `onlines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `onlines` (
  `online_user_id` bigint(20) unsigned NOT NULL,
  `online_username` varchar(40) NOT NULL,
  `online_last_view` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`online_user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
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
  `post_content` mediumtext NOT NULL,
  `post_title` varchar(250) NOT NULL DEFAULT 'needs title',
  `post_modified` datetime DEFAULT '1970-01-01 00:00:00',
  `post_comments` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_views` int(11) NOT NULL DEFAULT '0',
  `post_likes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_dislikes` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_latest_comment_id` bigint(20) unsigned DEFAULT NULL,
  `post_latest_commenter_id` bigint(20) unsigned DEFAULT NULL,
  `post_latest_comment_excerpt` varchar(1240) DEFAULT NULL,
  `post_approved` tinyint(3) unsigned DEFAULT NULL,
  `post_nsfw` bigint(20) unsigned NOT NULL DEFAULT '0',
  `post_topic` varchar(32) NOT NULL DEFAULT 'misc',
  `post_prev_in_topic` bigint(20) unsigned DEFAULT NULL,
  `post_next_in_topic` bigint(20) unsigned DEFAULT NULL,
  PRIMARY KEY (`post_id`),
  KEY `post_author_index` (`post_author`),
  KEY `thread_approved_index` (`post_approved`),
  KEY `post_date_index` (`post_date`),
  KEY `post_modified_index` (`post_modified`),
  KEY `post_topic_index` (`post_topic`),
  KEY `post_title_index` (`post_title`),
  FULLTEXT KEY `post_title_content_index` (`post_title`,`post_content`)
) ENGINE=MyISAM AUTO_INCREMENT=1313099 DEFAULT CHARSET=utf8mb4;
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
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
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4;
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
  `user_previous_names` varchar(256) DEFAULT NULL,
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
  `user_aboutyou` mediumtext,
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
) ENGINE=MyISAM AUTO_INCREMENT=129853 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-01-14 15:20:49
