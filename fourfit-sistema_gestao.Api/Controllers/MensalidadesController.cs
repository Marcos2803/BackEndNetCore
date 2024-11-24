using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Mensalidade;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MensalidadesController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public MensalidadesController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Mensalidades cadastrado com sucesso", Type = typeof(MensalidadesViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(MensalidadesViewModels))]
        public async Task<IActionResult> Register(MensalidadesViewModels model)
        {
            try
            {
                var contasBancarias = await _unitOfWork.ContasBancariasServices.ObterContasBancariasPorId(model.ContasBancariasId);
                if (contasBancarias == null)
                {
                    return NotFound("Contas bancarias não encontrado");
                }

                var formaPagamento = await _unitOfWork.FormaPagamentoServices.ObterFormaPagamentoPorId(model.FormaPagamentoId);
                if (formaPagamento == null)
                {
                    return NotFound("Forma de pagamento não encontrado");
                }

                var planos = await _unitOfWork.TipoPlanoServices.ObterPlanosPorId(model.PlanoId);

                if (planos == null)
                {
                    return NotFound("Plano não encontrado");
                }
                var mensalidades = new Mensalidades
                {
                    Id = model.Id,
                    AlunosId = model.AlunosId,
                    PlanoId = model.PlanoId,
                    FormaPagamentoId = model.FormaPagamentoId,
                    ContasBancariasId = model.ContasBancariasId,
                    ValorMensalidade = model.ValorMensalidade,
                    ValorMatricula = model.ValorMatricula,
                    MesReferente = model.MesReferente,
                    DataInicialPlano = model.DataInicialPlano,
                    DataPagamento = model.DataPagamento,
                    StatusPagamentos = model.StatusPagamentos,
                    StatusMensalidades = model.StatusMensalidades,

                };


                await _unitOfWork.MensalidadesServices.Cadastro(mensalidades);
                await _unitOfWork.MensalidadesServices.Salvar();

                var aluno = await _unitOfWork.AlunosServices.ObterPorId(mensalidades.AlunosId);
                aluno.StatusAlunos = StatusAlunosEnum.Ativo;
                await _unitOfWork.AlunosServices.Atualizar(aluno);
                await _unitOfWork.AlunosServices.Salvar();

                return Ok($"Mensalidade cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

       
        [HttpPut]
        [Route("Cancelar/{id}")]
        [SwaggerResponse(200, "Mensalidade cancelada com sucesso")]
        [SwaggerResponse(404, "Mensalidade não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Cancelar(int id)
        {
            try
            {
                var mensalidade = await _unitOfWork.MensalidadesServices.ObterPorId(id);
                if (mensalidade == null)
                {
                    return NotFound("Mensalidade não encontrado");
                }

                mensalidade.StatusMensalidades = StatusMensalidadesEnum.Cancelada;
                await _unitOfWork.MensalidadesServices.Atualizar(mensalidade);
                await _unitOfWork.MensalidadesServices.Salvar();


                var alunoId = mensalidade.AlunosId;
                var possuiMensalidadeAtiva = await _unitOfWork.MensalidadesServices.PossuiMensalidadeAtiva( alunoId);

                if (possuiMensalidadeAtiva == null)
                {
                    var aluno = await _unitOfWork.AlunosServices.ObterPorId(alunoId);
                    if (aluno != null)
                    {
                        aluno.StatusAlunos = StatusAlunosEnum.Inativo;
                        await _unitOfWork.AlunosServices.Atualizar(aluno);
                        await _unitOfWork.AlunosServices.Salvar();
                    }
                }

                return Ok("Mensalidade cancelada com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

        [HttpGet("BuscarAlunosMensalidades")]
        public async Task<IActionResult> BuscarUsuariosMensalidades()
        {
            var resultado = await _unitOfWork.UserServices.ObterUsuariosMensalidades();
            if (resultado != null)
            {
                return Ok(resultado);
            }
            return NotFound();
        }

        [HttpGet("BuscarPlanos")]
        public async Task<IActionResult> BuscarPlanosMensalidades()
        {
            var resultado = await _unitOfWork.TipoPlanoServices.ObterPlanosMensalidades();
            if (resultado != null)
            {
                return Ok(resultado);
            }
            return NotFound();
        }
    }
}
