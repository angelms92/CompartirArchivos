namespace CarpetaCompartida;

using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using System.Text;

class Program
{
    public struct Credenciales
    {
        public string User { get; set; }
        public string Password { get; set; }
        public string RutaCompartida { get; set; }
        public string RutaRecogida { get; set; }
        public string UsuarioCom { get; set; }
        public string PasswordUsuarioCom { get; set; }

    }

    static bool VerificadorDeContraseña()
    {
        var password = "MQAyADMA";

        bool esIgual;
        string? pswdIntroducida;
        do
        {
            Console.WriteLine("Dame la contraseña: ");
            pswdIntroducida = Console.ReadLine();
        } while (String.IsNullOrEmpty(pswdIntroducida));
        var pswdBytes = Encoding.Unicode.GetBytes(pswdIntroducida);
        var encriptarContra = Convert.ToBase64String(pswdBytes);
        esIgual = password == encriptarContra;
        return esIgual;
    }
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Uso: Programa.exe verificar | crear");
            return;
        }

        string opcion = args[0].ToLower();
        if (VerificadorDeContraseña())

        {
            Desencriptar();
            try
            {
                switch (opcion)
                {
                    case "1":
                        Verificador();
                        break;
                    case "2":
                        CrearFichero();
                        break;
                    default:
                        Console.WriteLine("Opción no válida. Usa 'verificar' o 'crear'.");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Se ha producido un error inesperado {ex.Message}");
            }
            Encriptar();
        }
        else
        {
            System.Console.WriteLine("La contraseña es incorrecta");
        }
    }


    public static void Verificador()
    {
        string jsonC = File.ReadAllText("UserPassword.json");
        Credenciales credencial = JsonSerializer.Deserialize<Credenciales>(jsonC);

        string carpeta = @"C:\Users\Ángel\Desktop\RedCompartida";
        string nombreCompartido = "RedCompartida";
        string rutaTaller = @"\\taller\ext\red";



        if (!Directory.Exists(carpeta))
        {
            Directory.CreateDirectory(carpeta);
            Console.WriteLine("Carpeta creada.");
        }

        // Compartir la carpeta usando 'net share'
        string comandoShare = $"Net share {nombreCompartido}={carpeta} /GRANT:todos,FULL";
        string comandoPermisos = $"icacls \"{carpeta}\" /grant red:(OI)(CI)F /T";
        string verificarJson = $"net use Z:\"{rutaTaller}\" /user:{credencial.User} {credencial.Password}";

        EjecutarComando(comandoShare);
        EjecutarComando(comandoPermisos);

        Console.WriteLine($"Carpeta '{nombreCompartido}' compartida correctamente.");

    }

    static void EjecutarComando(string comando)
    {
        Process proceso = new Process();
        proceso.StartInfo.FileName = "cmd.exe";
        proceso.StartInfo.Arguments = "/C " + comando;
        proceso.Start();
        proceso.WaitForExit();

    }
    static void CrearFichero()
    {
        string ruta = @"\\taller\ext\red";
        File.Create(Path.Combine(ruta, "hola.txt"));

    }


    static string Clave = "clave12345678901";

    static void Encriptar()
    {
        var contenido = File.ReadAllText("UserPassword.json");
        byte[] claveBytes = Encoding.UTF8.GetBytes(Clave);

        using (Aes aes = Aes.Create())
        {
            aes.Key = claveBytes;
            aes.GenerateIV(); // Vector de inicialización aleatorio
            var iv = aes.IV;

            using var encryptor = aes.CreateEncryptor(aes.Key, iv);
            byte[] contenidoBytes = Encoding.UTF8.GetBytes(contenido);
            byte[] encriptado = encryptor.TransformFinalBlock(contenidoBytes, 0, contenidoBytes.Length);

            // Guardamos IV + datos encriptados en base64
            byte[] resultado = new byte[iv.Length + encriptado.Length];
            Buffer.BlockCopy(iv, 0, resultado, 0, iv.Length);
            Buffer.BlockCopy(encriptado, 0, resultado, iv.Length, encriptado.Length);

            File.WriteAllText("UserPassword.json", "ENC:" + Convert.ToBase64String(resultado));
        }
    }

    static void Desencriptar()
    {
        string contenidoEncriptado = File.ReadAllText("UserPassword.json");

        if (!contenidoEncriptado.StartsWith("ENC:"))
        {
            Console.WriteLine("El archivo no parece estar encriptado. Se omite desencriptación.");
            return;
        }

        contenidoEncriptado = contenidoEncriptado.Substring(4); // Quitar el prefijo "ENC:"

        byte[] datos = Convert.FromBase64String(contenidoEncriptado);
        byte[] claveBytes = Encoding.UTF8.GetBytes(Clave);

        using (Aes aes = Aes.Create())
        {
            aes.Key = claveBytes;

            byte[] iv = new byte[16];
            byte[] encriptado = new byte[datos.Length - 16];

            Buffer.BlockCopy(datos, 0, iv, 0, 16);
            Buffer.BlockCopy(datos, 16, encriptado, 0, encriptado.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            byte[] desencriptado = decryptor.TransformFinalBlock(encriptado, 0, encriptado.Length);
            string contenido = Encoding.UTF8.GetString(desencriptado);

            File.WriteAllText("UserPassword.json", contenido);
        }
    }
}
