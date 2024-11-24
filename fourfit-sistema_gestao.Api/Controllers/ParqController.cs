using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.Parq;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ParqController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ParqController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Par-q cadastrado com sucesso", Type = typeof(ParqViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ParqViewModels))]
        public async Task<IActionResult> Register(ParqViewModels model)
        {
            try
            {
                var alunos = new Parq
                {
                    Id = model.Id,
                    DataPreenchimento = DateTime.Now,
                    AlunoId = model.AlunoId,
                    ProblemaCardiaco = model.ProblemaCardiaco,
                    DorNoPeitoAoSeExercitar = model.DorNoPeitoAoSeExercitar,
                    DesmaiaOuSenteTontura = model.DesmaiaOuSenteTontura,
                    ProblemaOssosOuArticulacoes = model.ProblemaOssosOuArticulacoes,
                    TomaMedicamentosPressaoCardiaco = model.TomaMedicamentosPressaoCardiaco,
                    MotivoFisicoOuDeSaude = model.MotivoFisicoOuDeSaude,

                };

                await _unitOfWork.ParqServices.Cadastro(alunos);
                await _unitOfWork.ParqServices.Salvar();
                return Ok($"Par-q cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Par-q excluído com sucesso")]
        [SwaggerResponse(404, "Par-q não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var parq = await _unitOfWork.ParqServices.ObterPorId(id);
                if (parq == null)
                {
                    return NotFound("Parq não encontrado");
                }

                await _unitOfWork.ParqServices.Deletar(id);
                await _unitOfWork.ParqServices.Salvar();

                return Ok("Parq excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
