-- MySQL Script generated by MySQL Workbench
-- Wed Jun 21 14:54:36 2017
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';

-- -----------------------------------------------------
-- Schema bdd_evalDouleur
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema bdd_evalDouleur
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `bdd_evalDouleur` DEFAULT CHARACTER SET utf8 ;
USE `bdd_evalDouleur` ;

-- -----------------------------------------------------
-- Table `bdd_evalDouleur`.`utilisateur`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `bdd_evalDouleur`.`utilisateur` (
  `idutilisateur` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(45) NOT NULL,
  `password` VARCHAR(45) NOT NULL,
  `nom` VARCHAR(45) NOT NULL,
  `prenom` VARCHAR(45) NOT NULL,
  `fonction` ENUM('administrateur', 'docteur', 'infirmier', 'patient') NOT NULL,
  `date_inscr` DATE NOT NULL,
  PRIMARY KEY (`idutilisateur`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `bdd_evalDouleur`.`type_eval`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `bdd_evalDouleur`.`type_eval` (
  `idtype_eval` INT NOT NULL AUTO_INCREMENT,
  `type_eval` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`idtype_eval`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `bdd_evalDouleur`.`eval`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `bdd_evalDouleur`.`eval` (
  `ideval` INT NOT NULL AUTO_INCREMENT,
  `utilisateur_idutilisateur` INT NOT NULL,
  `type_eval_idtype_eval` INT NOT NULL,
  `date_creation` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`ideval`),
  INDEX `fk_eval_utilisateur_idx` (`utilisateur_idutilisateur` ASC),
  INDEX `fk_eval_type_eval1_idx` (`type_eval_idtype_eval` ASC),
  CONSTRAINT `fk_eval_utilisateur`
    FOREIGN KEY (`utilisateur_idutilisateur`)
    REFERENCES `bdd_evalDouleur`.`utilisateur` (`idutilisateur`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_eval_type_eval1`
    FOREIGN KEY (`type_eval_idtype_eval`)
    REFERENCES `bdd_evalDouleur`.`type_eval` (`idtype_eval`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `bdd_evalDouleur`.`valeurs_eval`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `bdd_evalDouleur`.`valeurs_eval` (
  `idvaleurs_eval` INT NOT NULL AUTO_INCREMENT,
  `eval_ideval` INT NOT NULL,
  `value` INT NOT NULL,
  `temps_mesure` DATETIME NOT NULL,
  PRIMARY KEY (`idvaleurs_eval`),
  INDEX `fk_valeurs_eval_eval1_idx` (`eval_ideval` ASC),
  CONSTRAINT `fk_valeurs_eval_eval1`
    FOREIGN KEY (`eval_ideval`)
    REFERENCES `bdd_evalDouleur`.`eval` (`ideval`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;