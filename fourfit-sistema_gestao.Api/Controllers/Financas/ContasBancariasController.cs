using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.ContaBancaria;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers.Financas
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContasBancariasController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ContasBancariasController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Contas bancária cadastrado com sucesso", Type = typeof(ContasBancariasViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ContasBancariasViewModels))]
        public async Task<IActionResult> Register(ContasBancariasViewModels model)
        {
            try
            {
                var contasbancarias = new ContasBancarias
                {
                    Id = model.Id,
                    Bancos = model.Bancos,
                    Descricao = model.Descricao,
                    Status = model.Status,

                };

                await _unitOfWork.ContasBancariasServices.Cadastro(contasbancarias);
                await _unitOfWork.ContasBancariasServices.Salvar();
                return Ok($"Conta bancária cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
                
            }
        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações da conta bancária obtidas com sucesso", typeof(ContasBancariasUpdateViewModels))]
        [SwaggerResponse(404, "Conta bancária não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var contasbancarias = await _unitOfWork.ContasBancariasServices.ObterContasBancariasPorId(id);

            if (contasbancarias == null)
            {
                return NotFound("Conta bancária não encontrado");
            }

            var contasbancariasView = new ContasBancariasUpdateViewModels
            {
                Id = contasbancarias.Id,
                Bancos = contasbancarias.Bancos,
                Descricao = contasbancarias.Descricao,
                Status = contasbancarias.Status,
               
            };

            return Ok(contasbancariasView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Conta bancária atualizado com sucesso", Type = typeof(ContasBancariasUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Conta bancária não encontrado", Type = typeof(ContasBancariasUpdateViewModels))]
        public async Task<IActionResult> Update(ContasBancariasUpdateViewModels model)
        {
            try
            {

                var contasbancarias = await _unitOfWork.ContasBancariasServices.ObterPorId(model.Id);
                if (contasbancarias == null)
                {
                    return NotFound("Conta bancária não encontrado");
                }

                contasbancarias.Id = model.Id;
                contasbancarias.Bancos = model.Bancos;
                contasbancarias.Descricao = model.Descricao;
                contasbancarias.Status = model.Status;
                

                await _unitOfWork.ContasBancariasServices.Atualizar(contasbancarias);
                await _unitOfWork.ContasBancariasServices.Salvar();

                return Ok($"Conta bancária atualizada com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Conta bancária excluída com sucesso")]
        [SwaggerResponse(404, "Conta bancária não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var contabancaria = await _unitOfWork.ContasBancariasServices.ObterPorId(id);
                if (contabancaria == null)
                {
                    return NotFound("Conta Bancária não encontrada");
                }

                await _unitOfWork.ContasBancariasServices.Deletar(id);
                await _unitOfWork.ContasBancariasServices.Salvar();

                return Ok("Conta bancária excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
