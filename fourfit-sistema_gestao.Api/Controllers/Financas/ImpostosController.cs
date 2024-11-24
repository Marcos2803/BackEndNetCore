using fourfit.sistema_gestao.Domain.Entities.Financas;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.Impostos;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers.Financas
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImpostosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ImpostosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Imposto cadastrado com sucesso", Type = typeof(ImpostosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ImpostosViewModels))]
        public async Task<IActionResult> Register(ImpostosViewModels model)
        {
            try
            {
                var impostos = new Impostos
                {
                    Id = model.Id,
                    NomeImposto = model.NomeImposto,
                    
                };

                await _unitOfWork.ImpostosServices.Cadastro(impostos);
                await _unitOfWork.ImpostosServices.Salvar();
                return Ok($"Imposto cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }
        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do aluno obtidas com sucesso", typeof(ImpostosUpdateViewModels))]
        [SwaggerResponse(404, "Imposto não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var impostos = await _unitOfWork.ImpostosServices.ObterImpostosPorId(id);

            if (impostos == null)
            {
                return NotFound("Imposto não encontrado");
            }

            var impostosView = new ImpostosUpdateViewModels
            {
                Id = impostos.Id,
                NomeImposto = impostos.NomeImposto,
                
            };

            return Ok(impostosView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Imposto atualizado com sucesso", Type = typeof(ImpostosUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Imposto não encontrado", Type = typeof(ImpostosUpdateViewModels))]
        public async Task<IActionResult> Update(ImpostosUpdateViewModels model)
        {
            try
            {

                var impostos = await _unitOfWork.ImpostosServices.ObterPorId(model.Id);
                if (impostos == null)
                {
                    return NotFound("Imposto não encontrado");
                }


                impostos.NomeImposto = model.NomeImposto;
                

                await _unitOfWork.ImpostosServices.Atualizar(impostos);
                await _unitOfWork.ImpostosServices.Salvar();

                return Ok($"Imposto atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Imposto excluído com sucesso")]
        [SwaggerResponse(404, "Imposto não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var impostos = await _unitOfWork.ImpostosServices.ObterPorId(id);
                if (impostos == null)
                {
                    return NotFound("Imposto não encontrado");
                }

                await _unitOfWork.ImpostosServices.Deletar(id);
                await _unitOfWork.ImpostosServices.Salvar();

                return Ok("Imposto excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
