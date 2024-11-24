using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.PersonalRecords;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PersonalRecordController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public PersonalRecordController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Personal record cadastrado com sucesso", Type = typeof(PersonalRecordViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(PersonalRecordViewModels))]
        public async Task<IActionResult> Register(PersonalRecordViewModels model)
        {
            try
            {
                var personalpecord = new PersonalRecord
                {
                    Id = model.Id,
                    DataPR = DateTime.Now,
                    AlunosId = model.AlunosId,
                    ExerciciosId = model.ExerciciosId,
                    PesoPR = model.PesoPR,
                    Observacao = model.Observacao,

                };

                await _unitOfWork.PersonalRecordServices.Cadastro(personalpecord);
                await _unitOfWork.PersonalRecordServices.Salvar();
                return Ok($"Personal Record cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        //[HttpGet]
        //[Route("Update/{id}")]
        //[SwaggerResponse(200, "Informações do personal record obtidas com sucesso", typeof(PersonalRecordUpdateViewModels))]
        //[SwaggerResponse(404, "Personal record não encontrado")]
        //public async Task<IActionResult> Update(int id)
        //{
        //    var personalrecord = await _unitOfWork.PersonalRecordServices.ObterPersonalRecordPorId(id);

        //    if (personalrecord == null)
        //    {
        //        return NotFound("personal record não encontrado");
        //    }

        //    var personalrecordView = new PersonalRecordUpdateViewModels
        //    {
        //        Id = personalrecord.Id,
        //        AlunosId = personalrecord.AlunosId,
        //        ExerciciosId = personalrecord.ExerciciosId,
        //        PesoPR = personalrecord.PesoPR,
        //        DataPR = personalrecord.DataPR,
        //        Observacao = personalrecord.Observacao,
                
        //    };

        //    return Ok(personalrecordView);
        //}

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Personal record excluído com sucesso")]
        [SwaggerResponse(404, "Personal record não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var personalrecord = await _unitOfWork.PersonalRecordServices.ObterPorId(id);
                if (personalrecord == null)
                {
                    return NotFound("Personal record não encontrado");
                }

                await _unitOfWork.PersonalRecordServices.Deletar(id);
                await _unitOfWork.PersonalRecordServices.Salvar();

                return Ok("Personal record excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
