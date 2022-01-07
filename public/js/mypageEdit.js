import validate from './validate.js';

const $completeButton = document.querySelector('.complete-button');
const $email = document.querySelector('.mypage-form-email > input');
const $name = document.querySelector('.mypage-form-name > input');
const $phone = document.querySelector('.mypage-form-phone > input');
const $password = document.querySelector('.mypage-form-password > input');
const $confirmPwd = document.querySelector('#confirm-password');

let nowUserId;
let nowUserPassword;

window.onload = async () => {
  try {
    const { data: user } = await axios.get('/checkAuth');

    $email.value = user.email;
    $name.value = user.name;
    $phone.value = user.phone;

    nowUserId = user.id;
    nowUserPassword = user.password;
  } catch (e) {
    console.error(e);
  }
};

const INPUT_NAME_INDEX = 0;
const INPUT_PHONE_INDEX = 1;
const INPUT_PASSWORD_INDEX = 2;
const INPUT_CONFIRM_PASSWORD_INDEX = 3;

document.querySelector('.mypage-form').oninput = e => {
  if (e.target.matches('#name')) {
    validate.nameValidate(e.target.value, INPUT_NAME_INDEX, $completeButton);
  } else if (e.target.matches('#phone')) {
    validate.phoneValidate(e.target.value, INPUT_PHONE_INDEX, $completeButton);
  } else if (e.target.matches('#password')) {
    validate.passwordValidate(e.target.value, INPUT_PASSWORD_INDEX, $completeButton);

    const check = $password.parentNode.lastElementChild.textContent === '';
    if ($confirmPwd.value !== '') {
      validate.passwordConfirmValidate(
        !(check && $password.value === $confirmPwd.value),
        INPUT_CONFIRM_PASSWORD_INDEX,
        $completeButton
      );
    }
  } else if (e.target.matches('#confirm-password')) {
    const check = $password.parentNode.lastElementChild.textContent === '';
    validate.passwordConfirmValidate(
      !(check && $password.value === $confirmPwd.value),
      INPUT_CONFIRM_PASSWORD_INDEX,
      $completeButton
    );
  }
};

$completeButton.onclick = async e => {
  e.preventDefault();
  try {
    await axios.patch(`/users/${nowUserId}`, {
      name: $name.value,
      phone: $phone.value,
      password: $password.value,
    });

    window.location.href = '/mypage';
  } catch (e) {
    console.error(e);
  }
};

const $modal = document.querySelector('.popup');
const $modalError = $modal.querySelector('.error');
const $modalInput = $modal.querySelector('input');

const popupHandle = () => {
  document.querySelector('.cover').classList.toggle('hidden');
  $modal.classList.toggle('hidden');
  $modalError.textContent = '';
  $modalInput.value = '';
};

document.querySelector('.withdraw-button').onclick = () => {
  popupHandle();
};
$modal.querySelector('.cancle-button').onclick = () => {
  popupHandle();
};

const $deletePasswordCheck = $modal.querySelector('.delete-password');

$deletePasswordCheck.oninput = () => {
  if ($deletePasswordCheck.value === nowUserPassword) {
    $modal.querySelector('.delete-button').removeAttribute('disabled');
    $modalError.textContent = '';
  } else {
    $modalError.textContent = '비밀번호가 일치하지 않습니다!';
  }
};

$modal.querySelector('form').onsubmit = async e => {
  e.preventDefault();

  if (
    document.querySelector('.delete-button').getAttribute('disabled') ||
    $deletePasswordCheck.value !== nowUserPassword
  )
    return;

  try {
    const check = await axios.delete(`/users/${nowUserId}`);
    if (check.status === 204) window.location.href = '/signin';
  } catch (e) {
    console.error(e);
  }
};

document.querySelector('.form-back').onclick = () => (window.location.href = '/mypage');
