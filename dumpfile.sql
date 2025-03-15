-- MySQL dump 10.13  Distrib 9.2.0, for macos15.2 (arm64)
--
-- Host: 10.250.213.39    Database: db262
-- ------------------------------------------------------
-- Server version	9.2.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `db262`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `db262` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;

USE `db262`;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `messages` (
  `messageid` int NOT NULL AUTO_INCREMENT,
  `receiver` varchar(255) NOT NULL,
  `sender` varchar(255) NOT NULL,
  `message` varchar(255) DEFAULT NULL,
  `datetime` datetime DEFAULT CURRENT_TIMESTAMP,
  `isread` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`messageid`)
) ENGINE=InnoDB AUTO_INCREMENT=189 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `messages`
--

LOCK TABLES `messages` WRITE;
/*!40000 ALTER TABLE `messages` DISABLE KEYS */;
INSERT INTO `messages` VALUES (13,'est','sammi','hi','2025-02-24 13:55:39',1),(14,'est','sammi','how are you','2025-02-24 13:55:42',1),(15,'est','sammi','hello hello','2025-02-24 13:55:48',1),(36,'est','sammi','hi','2025-02-24 23:46:58',1),(37,'est','sammi','1','2025-02-24 23:47:04',1),(38,'est','sammi','2','2025-02-24 23:47:05',1),(39,'est','sammi','3','2025-02-24 23:47:07',1),(40,'est','sammi','4','2025-02-24 23:47:08',1),(41,'est','sammi','5','2025-02-24 23:47:09',1),(43,'est','sammi','heyyy','2025-02-24 23:49:18',1),(44,'est','sammi','how are you doing','2025-02-24 23:49:24',1),(45,'est','sammi','whats up?','2025-02-24 23:49:28',1),(46,'est','sammi','hey 1','2025-02-25 00:08:58',1),(47,'est','sammi','hey 2','2025-02-25 00:09:10',1),(48,'est','sammi','hey 3','2025-02-25 00:09:12',1),(49,'est','sammi','hey 4','2025-02-25 00:09:13',1),(50,'est','sammi','hey 5','2025-02-25 00:09:14',1),(51,'est','sammi','hey 6','2025-02-25 00:09:15',1),(52,'est','sammi','hey 7','2025-02-25 00:09:16',1),(53,'est','sammi','hey 8','2025-02-25 00:09:18',1),(62,'est','sammi','hi','2025-02-25 08:53:47',1),(64,'est','sammi','1','2025-02-25 09:07:45',1),(65,'est','sammi','2','2025-02-25 09:07:49',1),(66,'est','sammi','3','2025-02-25 09:07:50',1),(67,'est','sammi','4','2025-02-25 09:07:52',1),(68,'est','sammi','5','2025-02-25 09:07:53',1),(69,'est','sammi','6','2025-02-25 09:07:54',1),(87,'est','sammi','im good, you?','2025-02-25 09:18:24',1),(97,'est','sammi','hi esther!','2025-02-25 11:00:50',1),(99,'est','sammi','hi esther how are you?','2025-02-25 11:11:31',1),(118,'est','sammi','im good you?','2025-02-25 11:16:22',1),(130,'est','sammi','test test','2025-02-25 11:18:03',1),(131,'est','sammi','hi!','2025-02-25 11:19:34',1),(132,'est','sammi','hihi','2025-02-25 11:21:12',1),(133,'est','sammi','test test','2025-02-25 11:31:00',1),(134,'est','sammi','hi!!','2025-02-25 12:56:54',1),(135,'est','sammi','hi!!','2025-02-25 13:13:07',1),(138,'est','sammi','hi','2025-02-25 13:21:03',1),(140,'est','sammi','hi!','2025-02-25 13:22:51',1),(143,'est','sammi','hi','2025-02-25 13:29:22',1),(145,'est','sammi','bi','2025-02-25 13:31:21',1),(146,'est','sammi','hi','2025-02-25 13:34:04',1),(147,'est','sammi','hi','2025-02-25 13:34:38',1),(148,'est','sammi','hi!','2025-02-25 16:56:03',1),(149,'est','sammi','how are you?','2025-02-25 16:56:07',1),(152,'est1','wangzai','hi!!','2025-02-25 19:18:23',1),(155,'est1','wangzai','1','2025-02-25 19:19:24',1),(156,'est1','wangzai','2','2025-02-25 19:19:25',1),(157,'est1','wangzai','3','2025-02-25 19:19:27',1),(158,'est1','wangzai','4','2025-02-25 19:19:28',1),(159,'est1','wangzai','5','2025-02-25 19:19:29',1),(160,'est1','wangzai','6','2025-02-25 19:19:30',1),(161,'est1','wangzai','7','2025-02-25 19:19:31',1),(162,'est1','wangzai','8','2025-02-25 19:19:33',1),(163,'est1','wangzai','9','2025-02-25 19:19:35',1),(165,'est1','wangzai','11','2025-02-25 19:19:43',1),(166,'est1','wangzai','12','2025-02-25 19:19:45',1),(169,'est2','wangzai','yo','2025-02-25 19:27:50',1),(170,'est2','sammi','hiiii','2025-02-25 19:27:55',1),(171,'sammi','sammi','yo','2025-02-25 19:28:30',1),(172,'sammi','sammi','hiiiiiiiii','2025-02-25 19:28:49',1),(173,'sammi','wangzai','this is wangzai','2025-02-25 19:29:29',1);
/*!40000 ALTER TABLE `messages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `socket_id` varchar(255) DEFAULT NULL,
  `active` int NOT NULL DEFAULT '0',
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('est1','$2b$12$vAJ5Z3xWvXkIBFhwK6Rr1.fsoFB8/ojzlY2T8DqYfyUmErXsTH85W',NULL,0),('est2','$2b$12$R8dbHDBoTtlTeQZC/OzLnOghTQR.4uGDFax4eQcYuDkoYx1jxRhmq',NULL,0),('sammi','$2b$12$MooXQnyvoXKmSd.zO0u0juJs8/AXiGr0ETigBM6CsAGzs8ARL2Z9.','53153',1),('testuser_21wyq1','$2b$12$gf1tkTb8d/OC39ZbWd8Anem8F1aXLDuic0WxS2NyX9JsDL1zeocWa',NULL,0),('testuser_3xnhg7','$2b$12$qlqbDsfPnyqeam8fuwhAde1P1k8cez9XSLk9/CHbb4BmE3v3IaQuS',NULL,0),('testuser_6lqxqb','$2b$12$9OAmF7LtwEEyI32czQgB3uTUpxojJAzb9.sHff46i04FQwqopikTq',NULL,0),('testuser_c3jhzt','$2b$12$ek0v9hb3CPF7RMHgdOXNAeX8iI8yHdJ0GxIQeCTfTVHA6wyQRG1RC',NULL,0),('testuser_c6rzzm','$2b$12$sbVlpZlTCuj6rbLk1AL3H.tBpcvLYF2Jqd1JmLFwpGtQPq7gY0Yv6',NULL,0),('testuser_c8mfmi','$2b$12$dHBIeN9A4txv4EOnfNIH2OMlXE0qsbU5Iiaek0Afo6NW10xasrpDu',NULL,0),('testuser_eosxze','$2b$12$ot8HET.px5UvsAQrKy904urEwwTi91SN9lj.POlJQPd1DvBLNdmAq',NULL,0),('testuser_ffrf6u','$2b$12$7A1jfLZgbNtG1CakDH.S1eBPIsR734nIFVuIuhm9CBH69shW7bzni',NULL,0),('testuser_nqird1','$2b$12$cN.bbVqoqYvyCq/FUbkxSuLRSnZQHdHRMIlpQY6u2MxmMfdHU8ipu',NULL,0),('testuser_rqbar7','$2b$12$sU4hI93Tf32lgiLjbOk87.MYSyU4AOjhE6mg3/PEexZg7l8xZA5X.',NULL,0),('testuser_u23x9t','$2b$12$z2rzXgVpA4FmcORCBJLAtOE899xyTYMQ1j9PQkLCR2jnZIN9SdRla',NULL,0),('testuser_vz0mtm','$2b$12$9HrvhxvjwHSlm9VWztaV0OJUQHuAFzEXUiTA8Os3OS8aQn/ZSgwpO',NULL,0),('testuser_x3kuqq','$2b$12$Ypo22RGJbGdDGSkQmD.IQO8wNkrJ8CVDNTnSaez.I5iiVAu7Rh8LC',NULL,0),('testuser_yblg8n','$2b$12$VXY/yIaxSbbC5UQr/Mfjm.OLmhR0dGBvWKobPcVX.5AvEzwmv4upK',NULL,0),('testuser_zdera8','$2b$12$2SJxbIzobaUAC3k9EvtvNuF/dLB.YD8Ip.I/vC5SY6rwCES3dL3j2',NULL,0),('wangzai','$2b$12$tP2WaQmYPJB4tWLqoKVMPeW.zyUyGAG.vMWBII3/Umvpo7qyDAXOK',NULL,0);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-03-11 23:58:14
