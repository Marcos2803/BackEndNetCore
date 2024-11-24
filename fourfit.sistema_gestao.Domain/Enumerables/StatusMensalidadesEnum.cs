using System.ComponentModel;
namespace fourfit.sistema_gestao.Domain.Enumerables
{
    public enum StatusMensalidadesEnum
    {
        [Description("Ativo")]
        Ativo = 1,
        [Description("Inativo")]
        Inativo = 2,
        [Description("Pendente")]
        Pendente = 3,
        [Description("Cancelada")]
        Cancelada 
    }
}
