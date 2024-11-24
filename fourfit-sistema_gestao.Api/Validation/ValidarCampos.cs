namespace fourfit_sistema_gestao.Api.Validation
{
    public class ValidarCampos
    {
        public IEnumerable<string>? Erros { get; set; }
        public ValidarCampos(IEnumerable<string> erros)
        {
            Erros = erros;
        }
    }
}
