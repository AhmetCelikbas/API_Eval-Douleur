<?php
/*   CREDITS
 *   PROJECT : EVAL DOULEUR
 *   VERSION : 1
 *   DESCRIPTION : API FOR EVAL DOULEUR
 *   AUTHOR : AHMET CELIKBAS
 *   DATE : 21 - Jun - 2017
 */

/* DEPENDENCIES */
  ini_set('display_errors',1); // Affichages de toutes les erreurs
  error_reporting(E_ALL); // Affichages de toutes les erreurs
  require '../vendor/autoload.php'; // AUTOLOAD
  require '../vendor/firebase/php-jwt/src/JWT.php';

  use \Firebase\JWT\JWT;
  use Firebase\JWT\ExpiredException;
  use Firebase\JWT\SignatureInvalidException;

/* CONFIGURATION */
  /* ------------------ Logins  MySQL ------------------- */
    define('mysqlServer', 'localhost');
    define('mysqlUserName', 'root');
    define('mysqlUserPassword', 'root');
    define('mysqlDbName', 'bdd_evalDouleur');

  /* ------------------ CLE TOKEN JWT ------------------- */
    define('TokenKey', 'EVALDOULEUR'); // SECRET KEY OF TOKEN SIGNATURE VALIDATION
    define('TokenLifetime', 86400); // 1 day token lifetime (in seconds)
    JWT::$leeway = 60; // token clock skew time

  /* ------------------ ACCOUNT LEVELS ------------------- */
    define('administrator', 'administrateur');
    define('doctor', 'docteur');
    define('nurse', 'infirmier');
    define('patient', 'patient');

  /* ------------------ SLIM FRAMEWORK  ------------------- */
    $slimConfig = ['settings' => [
        'determineRouteBeforeAppMiddleware' => true,
        'displayErrorDetails' => true,
    ]];

/* MIDDLEWARE for cheking the request */
  class checkTokenOrLoginAttempt {

    private $container;

    public function __construct($container) {
        $this->container = $container;
    }

    public function __invoke($request, $response, $next){
      if ($request->isOptions()){
        return $response;  // ALLOW OPTION PRE REQUEST
      }


      $path = $request->getUri()->getPath();

      if(isset($request->getHeader('Authorization')[0])){
        $token =  $request->getHeader('Authorization')[0];
      } else {
        $token = null;
      }

  
      /* Check if the request is a login attempt */
        if($path  == "login"){
          return $next($request, $response); // Grant Access for login attempt
        }
      
      /* Check if the token exist in the request header */
        if (empty($token)){
          $responseData = array(
            'action' => 'tokenVerification', 
            'status' => 'fail', 
            'description' => 'Token not found or empty : '. $token
          );
          return $response->withJson($responseData, 401);  // Deny access (no token or empty token)
        }

      /* Check the token */
        try {
          $decoded = JWT::decode($token, TokenKey, array('HS256'));
        } catch(UnexpectedValueException $e) {
            // INVALID TOKEN (UNEXPECTED TOKEN VALUE)
            $responseData = array(
              'action' => 'tokenVerification', 
              'status' => 'fail', 
              'description' => 'Invalid token value : '. $token
            );
            return $response->withJson($responseData, 401);  // Deny access (Invalid token value)

        } catch(SignatureInvalidException $e) {
            // INVALID TOKEN (SIGNATURE VERIFICATION FAILED)
            $responseData = array(
              'action' => 'tokenVerification', 
              'status' => 'fail', 
              'description' => 'Token signature validity check failed : '. $token
            );
            return $response->withJson($responseData, 401);  // Deny access (Token signature validity check failed)

        } catch(ExpiredException $e) {
            // TOKEN EXPIRED (SIGNATURE VERIFICATION FAILED)
            $responseData = array(
              'action' => 'tokenVerification', 
              'status' => 'fail', 
              'description' => 'Token expired : '. $token
            );
            return $response->withJson($responseData, 401);  // Deny access (Token expired)
      
        }

      /* THE TOKEN IS VALID -> GRANT ACCESS TO THE API */
        $this->container['idUserOfTokenOwner'] = $decoded->idUser; //Store User id in a container 
        return $next($request, $response);
    }
  }

/* SLIM framework init */
  /* Headers */
  header("Access-Control-Allow-Origin: *");
  header("Access-Control-Allow-Methods: GET,PUT,POST,DELETE,PATCH,OPTIONS");
  header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Authorization");

  $app = new Slim\App($slimConfig); // Init Slim with the defined config
  $container = $app->getContainer(); // Application container
  $app->add(new checkTokenOrLoginAttempt($container)); // Add the request cheking middleware



/* Containers */
  /* MySQL */
    $container['mysql'] = function() {
        $pdo = new PDO("mysql:host=".mysqlServer.";dbname=".mysqlDbName."", mysqlUserName, mysqlUserPassword);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    };

  /* Database */
    class Database {
      private $pdo;
      public function __construct($pdo) {
        $this->pdo = $pdo;
      }
      public function query($sql) {
        $req = $this->pdo->prepare($sql);
        if($req->execute()){
          return $req;
        } else {
          return null;
        }
      }

      public function getLastId() {
        return $this->pdo->lastInsertId();
      }
    }
    $container['db'] = function($container) {
        return new Database($container->mysql);
    };

  /* Token owner user data */
    class userData {
      private $db;
      private $userData;

      public function __construct($db) {
        $this->db = $db;
      }

      public function getUserData($idUser) { 
        $this->userData = $this->db->query("select * from utilisateur where idutilisateur = '" . $idUser ."'");
        if($this->userData->rowCount() > 0) {
          return $this->userData->fetch(PDO::FETCH_ASSOC);
        } else {
          return null;
        }
      }

    }

    $container['userData'] = function($container) {
      return new userData($container->db);
    };






/* ----------------------- API ENDPOINTS START HERE ------------------------- */

/* API HOME */
  $app->get('/', function ($request, $response, $args) {
      return $response->write("API EVAL DOULEUR");
  });


/* LOGIN */
  $app->post("/login", function ($request, $response) {
    /* Query the database with the user credentials */
      $userCredsCheckRequest = $this->db->query("select idutilisateur from utilisateur where username = '" . $request->getParam("username") ."' AND password = '". $request->getParam("password") ."'"); 
    /* Check user credentials */
      if($userCredsCheckRequest->rowCount() > 0) {
        /* If the user credentials are good */
          $idUser = $userCredsCheckRequest->fetch(PDO::FETCH_NUM)[0];

          // Create a new token for website
          $tokenData = array(
            "iss" => $_SERVER['SERVER_NAME'],
            "iat" => time(), // Token creation Timestamp
            "exp" => time() + TokenLifetime,
            "idUser" => $idUser
          );

          $token = JWT::encode($tokenData, TokenKey); // CREATE THE TOKEN

          // Success reponse data
            $responseData = array(
              'action' => 'login', 
              'status' => 'success', 
              'description' => 'Loged in successfully',
              'token' => $token,
              'userData' => $this->userData->getUserData($idUser),
            );
          return $response->withJson($responseData, 200);
      } else { 
        // If the user credentials are bad
          $responseData = array(
            'action' => 'login', 
            'status' => 'fail', 
            'description' => 'Username or password do not match'
          );

        return $response->withJson($responseData, 401);
      }

    
  });


/* POST CREATE-USER */
  $app->post("/create-user", function ($request, $response) { 
    // We check what type of user we want to create
    if($request->getParam("fonction") == administrator) {
      // token user must be administrator
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'You must be administrator to create an new administrator account'
        );
        return $response->withJson($responseData, 401);
      }

      /* Check if the username is available */
      $usernameCheckRequest = $this->db->query("select idutilisateur from utilisateur where username = '" . $request->getParam("username") ."'"); 
      if($usernameCheckRequest->rowCount() != 0) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Username "'. $request->getParam("username") .'" is not available'
        );
        return $response->withJson($responseData, 409);
      }

      // Access granted -> create new account
      $query = $this->db->query("INSERT INTO utilisateur VALUES (
        NULL,
        '" .addslashes($request->getParam("username")). "', 
        '" .addslashes($request->getParam("password")). "', 
        '" .addslashes($request->getParam("nom")). "', 
        '" .addslashes($request->getParam("prenom")). "', 
        '" .addslashes($request->getParam("fonction")). "', 
        '" .date("Y-m-d"). "'
        )"); 

      if($query->rowCount() < 1) {
        // Error
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Error creating the new administrator'
        );
        return $response->withJson($responseData, 424);
      }
      
      $responseData = array(
        'action' => 'create-user', 
        'status' => 'success', 
        'description' => 'New administrator created'
      );
      return $response->withJson($responseData, 200);

    } else if($request->getParam("fonction") == doctor) {

      // token user must be administrator
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'You must be administrator to create an new doctor account'
        );
        return $response->withJson($responseData, 401);
      }

      /* Check if the username is available */
      $usernameCheckRequest = $this->db->query("select idutilisateur from utilisateur where username = '" . $request->getParam("username") ."'"); 
      if($usernameCheckRequest->rowCount() != 0) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Username "'. $request->getParam("username") .'" is not available'
        );
        return $response->withJson($responseData, 409);
      }

      // Access granted -> create new account
      $query = $this->db->query("INSERT INTO utilisateur VALUES (
        NULL,
        '" .addslashes($request->getParam("username")). "', 
        '" .addslashes($request->getParam("password")). "', 
        '" .addslashes($request->getParam("nom")). "', 
        '" .addslashes($request->getParam("prenom")). "', 
        '" .addslashes($request->getParam("fonction")). "', 
        '" .date("Y-m-d"). "'
        )"); 

      if($query->rowCount() < 1) {
        // Error
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Error creating the new doctor'
        );
        return $response->withJson($responseData, 424);
      }
      
      $responseData = array(
        'action' => 'create-user', 
        'status' => 'success', 
        'description' => 'New doctor created'
      );
      return $response->withJson($responseData, 200);

    } else if($request->getParam("fonction") == nurse) {

      // token user must be administrator or doctor
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
        if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
          // Access denied
          $responseData = array(
            'action' => 'create-user', 
            'status' => 'fail', 
            'description' => 'You must be administrator or doctor to create an new nurse'
          );
          return $response->withJson($responseData, 401);
        }
      }

      /* Check if the username is available */
      $usernameCheckRequest = $this->db->query("select idutilisateur from utilisateur where username = '" . $request->getParam("username") ."'"); 
      if($usernameCheckRequest->rowCount() != 0) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Username "'. $request->getParam("username") .'" is not available'
        );
        return $response->withJson($responseData, 409);
      }

      // Access granted -> create new account
      $query = $this->db->query("INSERT INTO utilisateur VALUES (
        NULL,
        '" .addslashes($request->getParam("username")). "', 
        '" .addslashes($request->getParam("password")). "', 
        '" .addslashes($request->getParam("nom")). "', 
        '" .addslashes($request->getParam("prenom")). "', 
        '" .addslashes($request->getParam("fonction")). "', 
        '" .date("Y-m-d"). "'
        )"); 

      if($query->rowCount() < 1) {
        // Error
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Error creating the new nurse'
        );
        return $response->withJson($responseData, 424);
      }
      
      $responseData = array(
        'action' => 'create-user', 
        'status' => 'success', 
        'description' => 'New nurse created'
      );
      return $response->withJson($responseData, 200);


    } else if($request->getParam("fonction") == patient) {

      // token user must be doctor
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'You must be doctor to create an new patient'
        );
        return $response->withJson($responseData, 401);
      }

      /* Check if the username is available */
      $usernameCheckRequest = $this->db->query("select idutilisateur from utilisateur where username = '" . $request->getParam("username") ."'"); 
      if($usernameCheckRequest->rowCount() != 0) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Username "'. $request->getParam("username") .'" is not available'
        );
        return $response->withJson($responseData, 409);
      }

      // Access granted -> create new account
      $query = $this->db->query("INSERT INTO utilisateur VALUES (
        NULL,
        '" .addslashes($request->getParam("username")). "', 
        '" .addslashes($request->getParam("password")). "', 
        '" .addslashes($request->getParam("nom")). "', 
        '" .addslashes($request->getParam("prenom")). "', 
        '" .addslashes($request->getParam("fonction")). "', 
        '" .date("Y-m-d"). "'
        )"); 

      if($query->rowCount() < 1) {
        // Error
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'Error creating the new patient'
        );
        return $response->withJson($responseData, 424);
      }
      
      $responseData = array(
        'action' => 'create-user', 
        'status' => 'success', 
        'description' => 'New patient created'
      );
      return $response->withJson($responseData, 200);


    } else {
      // Access denied
      $responseData = array(
        'action' => 'create-user', 
        'status' => 'fail', 
        'description' => 'Unknown type of account : ' . $request->getParam("fonction")
      );
      return $response->withJson($responseData, 401);
    }
  });


/* POST CREATE-EVAL-TYPE */
  $app->post("/create-eval-type", function ($request, $response) {

    if(empty($request->getParam("type_eval"))) {
      // Access denied
      $responseData = array(
        'action' => 'create-eval-type', 
        'status' => 'fail', 
        'description' => 'Evaluation type is empty'
      );
      return $response->withJson($responseData, 401);
    }

    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
      // Access denied
      $responseData = array(
        'action' => 'create-eval-type', 
        'status' => 'fail', 
        'description' => 'You must be administrator to create an new evaluation type'
      );
      return $response->withJson($responseData, 401);
    }

    /* Check if the type is available */
      $usernameCheckRequest = $this->db->query("select idtype_eval from type_eval where type_eval = '" . $request->getParam("type_eval") ."'"); 
      if($usernameCheckRequest->rowCount() != 0) {
        // Access denied
        $responseData = array(
          'action' => 'create-eval-type', 
          'status' => 'fail', 
          'description' => 'Evaluation type "'. $request->getParam("type_eval") .'" already exist'
        );
        return $response->withJson($responseData, 409);
      }

      // Access granted -> create new eval type
      $query = $this->db->query("INSERT INTO type_eval VALUES (
        NULL,
        '" .addslashes($request->getParam("type_eval")). "'
        )"); 

      if($query->rowCount() < 1) {
        // Error
        $responseData = array(
          'action' => 'create-eval-type', 
          'status' => 'fail', 
          'description' => 'Error creating the new evaluation type'
        );
        return $response->withJson($responseData, 424);
      }

      $responseData = array(
        'action' => 'create-eval-type', 
        'status' => 'success', 
        'description' => 'New evaluation type created'
      );
      return $response->withJson($responseData, 200);

  });



/* POST CREATE-EVAL */
  $app->post("/create-eval", function ($request, $response) {

    $id_patient = $request->getParam("id_patient");
    $id_type_eval = $request->getParam("id_type_eval");
    if(!isset($id_patient) OR !isset($id_type_eval)) {
      // Access denied
      $responseData = array(
        'action' => 'create-eval-type', 
        'status' => 'fail', 
        'description' => 'Evaluation type or patient id is empty'
      );
      return $response->withJson($responseData, 401);
    }

    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
        // Access denied
        $responseData = array(
          'action' => 'create-user', 
          'status' => 'fail', 
          'description' => 'You must be doctor or nurse to create an new evaluation'
        );
        return $response->withJson($responseData, 401);
      }
    }

    // Access granted -> create new eval
    $query = $this->db->query("INSERT INTO eval VALUES (
      NULL,
      '" .addslashes($request->getParam("id_patient")). "',
      '" .addslashes($request->getParam("id_type_eval")). "',
      '" .date("Y-m-d H:i:s"). "'
      )"); 

    if($query->rowCount() < 1) {
      // Error
      $responseData = array(
        'action' => 'create-eval-type', 
        'status' => 'fail', 
        'description' => 'Error creating the new evaluation'
      );
      return $response->withJson($responseData, 424);
    }

    $responseData = array(
      'action' => 'create-eval-type', 
      'status' => 'success', 
      'description' => 'New evaluation created'
    );
    return $response->withJson($responseData, 200);
  });


/* POST EVAL-VALUE */
  $app->post("/eval-value", function ($request, $response) {
    
    $id_eval = $request->getParam("id_eval");
    $value = $request->getParam("value");
   
   
    if(!isset($id_eval) OR !isset($value)) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Evaluation id or value is empty'
      );
      return $response->withJson($responseData, 401);
    }

    if($value < 1 OR $value > 10) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Evaluation value out of range (1 to 10)'
      );
      return $response->withJson($responseData, 401);
    }

    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
        if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != patient) {
          // Access denied
          $responseData = array(
            'action' => 'eval-value', 
            'status' => 'fail', 
            'description' => 'You must be doctor or nurse or patient to create an new evaluation value'
          );
          return $response->withJson($responseData, 401);
        }
      }
    }
    
    /* Check if the evaluation exist */
    $evalCountCheckRequest = $this->db->query("select * from eval where ideval = '" . $request->getParam("id_eval") ."'"); 
    if($evalCountCheckRequest->rowCount() == 0) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Cannot found evaluation with id : ' . $request->getParam("id_eval")
      );
      return $response->withJson($responseData, 409);
    }

    /* Check we have less than 7 values */
    $evalCountCheckRequest = $this->db->query("select idvaleurs_eval from valeurs_eval where eval_ideval = '" . $request->getParam("id_eval") ."'"); 
    if($evalCountCheckRequest->rowCount() > 6) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Value not added, evaluation already completed.'
      );
      return $response->withJson($responseData, 409);
    }

    // Access granted -> create new eval value
    $query = $this->db->query("INSERT INTO valeurs_eval VALUES (
      NULL,
      '" .$request->getParam("id_eval"). "',
      '" .$request->getParam("value"). "',
      '" .date("Y-m-d H:i:s"). "'
      )"); 

    if($query->rowCount() < 1) {
      // Error
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Error creating the new evaluation value'
      );
      return $response->withJson($responseData, 424);
    }

    $responseData = array(
      'action' => 'eval-value', 
      'status' => 'success', 
      'description' => 'New evaluation value created'
    );
    return $response->withJson($responseData, 200);

  });


/* GET EVALS FOR PATIENT */
  $app->get("/evals/{id_patient}", function ($request, $response, $args) {
    
    if(!isset($args["id_patient"])) {
      // Access denied
      $responseData = array(
        'action' => 'eval', 
        'status' => 'fail', 
        'description' => 'Patient id is empty'
      );
      return $response->withJson($responseData, 401);
    }

    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
        if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != patient) {
          // Access denied
          $responseData = array(
            'action' => 'eval', 
            'status' => 'fail', 
            'description' => 'You must be doctor or nurse or patient to get evaluations'
          );
          return $response->withJson($responseData, 401);
        }
      }
    }

    // Check if the patient exist 
    $patientQuery = $this->db->query("select * from utilisateur where idutilisateur = '" . $args["id_patient"] ."'"); 
    if($patientQuery->rowCount() == 0) {
      // Access denied
      $responseData = array(
        'action' => 'eval', 
        'status' => 'fail', 
        'description' => 'Cannot found patient with id : ' . $args["id_patient"]
      );
      return $response->withJson($responseData, 409);
    }
    
    // Access granted -> get eval values
      $evalsQuery = $this->db->query("select ideval, type_eval_idtype_eval, date_creation from eval where utilisateur_idutilisateur = '" . $args["id_patient"] ."'"); 
      $evals = array();
      while($eval = $evalsQuery->fetch(PDO::FETCH_ASSOC)){


        $evalsQuery = $this->db->query("select type_eval from type_eval where idtype_eval = '" . $eval["type_eval_idtype_eval"] ."'"); 
        $eval["type_eval"] = $evalsQuery->fetch(PDO::FETCH_NUM)[0];



        $valuesQuery = $this->db->query("select * from valeurs_eval where eval_ideval = '" . $eval["ideval"] ."'");


        $values = array();
        while($value = $valuesQuery->fetch(PDO::FETCH_ASSOC)){
          array_push($values, $value);
        }



        $eval["values"] = $values;



        array_push($evals, $eval);
      }

    $responseData = array(
      'action' => 'eval-value', 
      'status' => 'success', 
      'patient' => $patientQuery->fetch(PDO::FETCH_ASSOC),
      'evals' => $evals
    );
    return $response->withJson($responseData, 200);

  });

/* GET PATIENTS */
  $app->get("/patients", function ($request, $response, $args) {
    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
        if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
          // Access denied
          $responseData = array(
            'action' => 'eval', 
            'status' => 'fail', 
            'description' => 'You must be doctor or nurse or patient to get patients list'
          );
          return $response->withJson($responseData, 401);
        }
      }
    }

    // Access granted -> get eval values
      $patientsQuery = $this->db->query("select * from utilisateur"); 

      $patients = array();
      while($patient = $patientsQuery->fetch(PDO::FETCH_ASSOC)){
        array_push($patients, $patient);
      }

    $responseData = array(
      'action' => 'patients', 
      'status' => 'success', 
      'patients' => $patients,
    );
    return $response->withJson($responseData, 200);

  });



/* GET EVAL-TYPE */
  $app->get("/eval-type", function ($request, $response, $args) {
    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != administrator) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
        if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
          if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != patient) {
            // Access denied
            $responseData = array(
              'action' => 'eval', 
              'status' => 'fail', 
              'description' => 'You must be doctor or nurse or patient to get patients list'
            );
            return $response->withJson($responseData, 401);
          }
        }
      }
    }

    // Access granted -> get eval values
      $evalTypesQuery = $this->db->query("select * from type_eval"); 

      $evalTypes = array();
      while($evalType = $evalTypesQuery->fetch(PDO::FETCH_ASSOC)){
        array_push($evalTypes, $evalType);
      }

    $responseData = array(
      'action' => 'eval-ypes', 
      'status' => 'success', 
      'patients' => $evalTypes,
    );
    return $response->withJson($responseData, 200);

  });




/* PUT EVAL-VALUE */
  $app->put("/eval-value", function ($request, $response) {
    
    $id_value = $request->getParam("id_value");
    $value = $request->getParam("value");
   
   
    if(!isset($id_value) OR !isset($value)) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Value id or value is empty'
      );
      return $response->withJson($responseData, 401);
    }

    // check if the value is in the range of 1 to 10
    if($value < 1 OR $value > 10) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Evaluation value out of range (1 to 10)'
      );
      return $response->withJson($responseData, 401);
    }

    // token user must be nurse or doctor
    if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != doctor) {
      if($this->userData->getUserData($this->idUserOfTokenOwner)['fonction'] != nurse) {
        // Access denied
        $responseData = array(
          'action' => 'eval-value', 
          'status' => 'fail', 
          'description' => 'You must be doctor or nurse or patient to update an evaluation value'
        );
        return $response->withJson($responseData, 401);
      }
    }
    
    /* Check if the value exist */
    $evalCountCheckRequest = $this->db->query("select * from valeurs_eval where idvaleurs_eval = '" . $request->getParam("id_value") ."'"); 
    if($evalCountCheckRequest->rowCount() == 0) {
      // Access denied
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Cannot found evaluation value with id : ' . $request->getParam("id_value")
      );
      return $response->withJson($responseData, 409);
    }

    // Access granted -> update value
    $query = $this->db->query("UPDATE valeurs_eval set value='". $request->getParam("value") ."', temps_mesure='". date("Y-m-d H:i:s") ."' where idvaleurs_eval='". $request->getParam("id_value") ."'"); 
    if($query->rowCount() < 1) {
      // Error
      $responseData = array(
        'action' => 'eval-value', 
        'status' => 'fail', 
        'description' => 'Error updating the new evaluation value'
      );
      return $response->withJson($responseData, 424);
    }

    $responseData = array(
      'action' => 'eval-value', 
      'status' => 'success', 
      'description' => 'Evaluation value updated'
    );
    return $response->withJson($responseData, 200);

  });



$app->run();
?>