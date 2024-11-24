using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Despesa;
using fourfit_sistema_gestao.Api.Models.Investimento;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers.Financas
{
    [Route("api/[controller]")]
    [ApiController]
    public class InvestimentosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public InvestimentosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Investimento cadastrado com sucesso", Type = typeof(InvestimentosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(InvestimentosViewModels))]
        public async Task<IActionResult> Register(InvestimentosViewModels model)
        {
            try
            {
                var investimentos = new Investimentos
                {
                    Id = model.Id,
                    FormaPagamentoId = model.FormaPagamentoId,
                    ContasBancariasId = model.ContasBancariasId,
                    Descricao = model.Descricao,
                    ValorInvestido = model.ValorInvestido,
                    DataVencimento = model.DataVencimento,
                    DataPagamento = model.DataPagamento,
                    StatusPagamentos = model.StatusPagamentos,
                    Observacao = model.Observacao,


                };

                await _unitOfWork.InvestimentosServices.Cadastro(investimentos);
                await _unitOfWork.InvestimentosServices.Salvar();
                return Ok($" Investimento cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Investimento excluído com sucesso")]
        [SwaggerResponse(404, "Investimento não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var investimento = await _unitOfWork.InvestimentosServices.ObterPorId(id);
                if (investimento == null)
                {
                    return NotFound("Investimento não encontrado");
                }

                await _unitOfWork.InvestimentosServices.Deletar(id);
                await _unitOfWork.InvestimentosServices.Salvar();

                return Ok("Investimento excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
